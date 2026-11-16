package daemon

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/ImanMontajabi/OpenWarp/internal/state"
)

// ExitLocation is where a tunnel leaves Cloudflare's network, as Cloudflare's trace reports it for a request
// sent through that tunnel. Companion apps (Rat) read it from the status: the WARP endpoint is an anycast
// address, so a geolocation database places it wherever the prefix is registered (Canada for 162.159.198.0/23),
// not in the data centre that carries the traffic.
type ExitLocation struct {
	Colo string // IATA code of the data centre, three letters ("DUS")
	Loc  string // ISO 3166-1 alpha-2 country of the exit address ("DE")
}

// exitRetry is how long lookupExit waits before each attempt: a trace sent the moment the tunnel came up can
// fail while routes and DNS settle. Tests shorten it.
var exitRetry = []time.Duration{0, 3 * time.Second, 10 * time.Second}

// exitFromTrace takes the exit from a trace's fields, or reports false when the request did not arrive through
// WARP (the colo would then be the one in front of the user's own connection) or a field is not well formed.
func exitFromTrace(m map[string]string) (ExitLocation, bool) {
	if w := m["warp"]; w != "on" && w != "plus" {
		return ExitLocation{}, false
	}
	colo, loc := m["colo"], m["loc"]
	if !letters(colo, 3) || !letters(loc, 2) || loc == "XX" || loc == "T1" {
		return ExitLocation{}, false
	}
	return ExitLocation{Colo: colo, Loc: loc}, true
}

// letters reports whether s is exactly n ASCII capital letters.
func letters(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < n; i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return false
		}
	}
	return true
}

// traceDial is how a trace request reaches Cloudflare for a session: the system's routes (through the tunnel in
// every tunnel mode), or the session's own netstack in proxy mode.
func traceDial(s *session) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if s.proxy != nil {
		return s.proxy.Dial
	}
	return (&net.Dialer{Timeout: 10 * time.Second}).DialContext
}

// lookupExit asks Cloudflare once, through session s, where it exits, and keeps the answer while s is the
// current session. DNS-only sessions have no tunnel and are not looked up. It gives up when s is replaced, the
// lookup is switched off, or every attempt failed (the status then has no colo; nothing is guessed).
func (e *Engine) lookupExit(ctx context.Context, s *session) {
	if s == nil || s.tr == nil {
		return
	}
	for i, wait := range exitRetry {
		if wait > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
		}
		if !e.wantsExitLookup(s) {
			return
		}
		tctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		m, err := e.probe.Trace(tctx, traceDial(s))
		cancel()
		if err == nil {
			if x, ok := exitFromTrace(m); ok {
				e.recordExit(s, x)
				return
			}
			if w := m["warp"]; w != "on" && w != "plus" {
				log.Printf("exit location: Cloudflare reports warp=%s; not recorded", orDash(w))
				return // the request went around the tunnel; asking again will not change that
			}
		}
		if i == len(exitRetry)-1 {
			log.Printf("exit location: no answer after %d attempts (last: %v)", len(exitRetry), err)
		}
	}
}

// wantsExitLookup reports whether s is still the connected session and the lookup is switched on.
func (e *Engine) wantsExitLookup(s *session) bool {
	e.store.Lock()
	off := e.store.S.Settings.DisableLocationLookup
	e.store.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	return !off && e.sess == s && e.exitSess != s
}

// recordExit keeps x as session s's exit, unless s is no longer the current session.
func (e *Engine) recordExit(s *session, x ExitLocation) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sess != s {
		return
	}
	e.exit, e.exitSess = x, s
	log.Printf("exit location: %s (%s)", x.Colo, x.Loc)
}

// locationSettingChanged looks the current session up when the lookup was just switched on, and forgets the
// exit when it was switched off. Neither reconnects.
func (e *Engine) locationSettingChanged(old, next state.Settings) {
	if old.DisableLocationLookup == next.DisableLocationLookup {
		return
	}
	e.mu.Lock()
	sess, connected := e.sess, e.status == StatusConnected
	if next.DisableLocationLookup {
		e.exit, e.exitSess = ExitLocation{}, nil
	}
	e.mu.Unlock()
	if !next.DisableLocationLookup && connected && sess != nil {
		go e.lookupExit(context.Background(), sess)
	}
}
