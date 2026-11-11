package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// SourceState separates "the source is down" (try again tomorrow, no issue) from "the source answered with
// something the monitor no longer understands" (the monitor needs updating: worth an issue).
type SourceState string

const (
	SourceOK      SourceState = "ok"
	SourceOutage  SourceState = "unavailable"
	SourceChanged SourceState = "format changed"
)

// FetchError carries the state a failure puts the source in.
type FetchError struct {
	State  SourceState
	Status int
	Err    error
}

func (e *FetchError) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("%s (HTTP %d): %v", e.State, e.Status, e.Err)
	}
	return fmt.Sprintf("%s: %v", e.State, e.Err)
}

func (e *FetchError) Unwrap() error { return e.Err }

func outage(status int, err error) error  { return &FetchError{SourceOutage, status, err} }
func changed(status int, err error) error { return &FetchError{SourceChanged, status, err} }

func stateOf(err error) SourceState {
	var fe *FetchError
	if errors.As(err, &fe) {
		return fe.State
	}
	if err != nil {
		return SourceOutage
	}
	return SourceOK
}

// Fetcher downloads one URL with a timeout, a size limit and a few retries for temporary failures.
type Fetcher struct {
	HTTP      *http.Client
	UserAgent string
	Attempts  int
	MaxBytes  int64
	// Sleep is replaced in tests.
	Sleep func(time.Duration)
	// MaxRetryAfter caps how long a Retry-After header can make the monitor wait.
	MaxRetryAfter time.Duration
	// Requests counts HTTP requests, so tests can assert the monitor stays cheap.
	Requests int
}

func NewFetcher() *Fetcher {
	return &Fetcher{
		HTTP:          &http.Client{Timeout: 25 * time.Second},
		UserAgent:     "OpenWarp-upstream-monitor (+https://github.com/ImanMontajabi/OpenWarp)",
		Attempts:      3,
		MaxBytes:      8 << 20,
		Sleep:         time.Sleep,
		MaxRetryAfter: 60 * time.Second,
	}
}

// Get returns the body of a 2xx response. headers are added to the request (an Authorization header for
// the GitHub API). 404/410 mean the source moved (changed); network errors, 5xx and 429/403 rate limits
// are an outage after the retries.
func (f *Fetcher) Get(ctx context.Context, url string, headers map[string]string) ([]byte, error) {
	var last error
	for attempt := 1; attempt <= f.Attempts; attempt++ {
		body, retryAfter, err := f.once(ctx, url, headers)
		if err == nil {
			return body, nil
		}
		last = err
		var fe *FetchError
		if errors.As(err, &fe) && fe.State == SourceChanged {
			return nil, err
		}
		if attempt == f.Attempts || ctx.Err() != nil {
			break
		}
		wait := time.Duration(attempt) * 2 * time.Second
		if retryAfter > 0 {
			wait = min(retryAfter, f.MaxRetryAfter)
		}
		f.Sleep(wait)
	}
	return nil, last
}

func (f *Fetcher) once(ctx context.Context, url string, headers map[string]string) ([]byte, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, changed(0, err)
	}
	req.Header.Set("User-Agent", f.UserAgent)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	f.Requests++
	resp, err := f.HTTP.Do(req)
	if err != nil {
		return nil, 0, outage(0, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, f.MaxBytes+1))
	if err != nil {
		return nil, 0, outage(resp.StatusCode, err)
	}
	switch {
	case resp.StatusCode/100 == 2:
		if int64(len(body)) > f.MaxBytes {
			return nil, 0, changed(resp.StatusCode, fmt.Errorf("response larger than %d bytes", f.MaxBytes))
		}
		return body, 0, nil
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		return nil, 0, changed(resp.StatusCode, errors.New("the source is gone or moved"))
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusForbidden || resp.StatusCode/100 == 5:
		return nil, retryAfter(resp.Header.Get("Retry-After")), outage(resp.StatusCode, errors.New(http.StatusText(resp.StatusCode)))
	default:
		return nil, 0, changed(resp.StatusCode, errors.New(http.StatusText(resp.StatusCode)))
	}
}

func retryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if s, err := strconv.Atoi(v); err == nil && s >= 0 {
		return time.Duration(s) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}
