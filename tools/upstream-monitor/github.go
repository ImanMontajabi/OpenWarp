package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// TrustedAuthor is the only account whose issue markers the monitor believes. Anyone can open an issue
// containing a marker; trusting those would let a stranger silence an alert.
const TrustedAuthor = "github-actions[bot]"

const issueLabel = "upstream-monitoring"

var ErrRateLimited = errors.New("GitHub API rate limit reached")

type labelDef struct{ Name, Color, Description string }

var monitorLabels = []labelDef{
	{issueLabel, "1D76DB", "Found by the upstream monitor"},
	{"compatibility", "FBCA04", "Compatibility with Cloudflare's service or official client"},
	{"needs-investigation", "D93F0B", "Needs a maintainer to investigate"},
	{"security", "B60205", "Security vulnerability or hardening"},
	{"dependencies", "0366D6", "Dependency updates"},
}

func labelsFor(k Kind) []string {
	switch k {
	case KindSecurity:
		return []string{issueLabel, "security", "needs-investigation"}
	case KindDependency:
		return []string{issueLabel, "security", "dependencies", "needs-investigation"}
	case KindCompatibility:
		return []string{issueLabel, "compatibility", "needs-investigation"}
	}
	return []string{issueLabel}
}

// GitHub is a minimal REST client for the few calls the monitor makes.
type GitHub struct {
	API, Repo, Token string
	HTTP             *http.Client
	Calls            int
}

type ghIssue struct {
	Number  int    `json:"number"`
	Title   string `json:"title"`
	Body    string `json:"body"`
	State   string `json:"state"`
	HTMLURL string `json:"html_url"`
	User    struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"user"`
	Labels []struct {
		Name string `json:"name"`
	} `json:"labels"`
	PullRequest json.RawMessage `json:"pull_request"`
}

func (g *GitHub) do(ctx context.Context, method, path string, in, out any) (int, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(g.API, "/")+path, body)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "OpenWarp-upstream-monitor")
	if g.Token != "" {
		req.Header.Set("Authorization", "Bearer "+g.Token)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	g.Calls++
	resp, err := g.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode == http.StatusTooManyRequests ||
		(resp.StatusCode == http.StatusForbidden && (resp.Header.Get("X-RateLimit-Remaining") == "0" || resp.Header.Get("Retry-After") != "")) {
		return resp.StatusCode, ErrRateLimited
	}
	if resp.StatusCode/100 != 2 {
		return resp.StatusCode, fmt.Errorf("GitHub API %s %s: HTTP %d: %s", method, path, resp.StatusCode, truncate(strings.TrimSpace(string(data)), 200))
	}
	if out != nil && len(data) > 0 {
		return resp.StatusCode, json.Unmarshal(data, out)
	}
	return resp.StatusCode, nil
}

// MonitorIssues lists open and closed issues with the monitor label (pull requests excluded).
func (g *GitHub) MonitorIssues(ctx context.Context) ([]ghIssue, error) {
	var all []ghIssue
	for page := 1; page <= 10; page++ {
		var batch []ghIssue
		path := fmt.Sprintf("/repos/%s/issues?labels=%s&state=all&per_page=100&page=%d", g.Repo, url.QueryEscape(issueLabel), page)
		if _, err := g.do(ctx, http.MethodGet, path, nil, &batch); err != nil {
			return nil, err
		}
		for _, is := range batch {
			if len(is.PullRequest) == 0 || string(is.PullRequest) == "null" {
				all = append(all, is)
			}
		}
		if len(batch) < 100 {
			break
		}
	}
	return all, nil
}

func (g *GitHub) EnsureLabels(ctx context.Context) error {
	for _, l := range monitorLabels {
		status, err := g.do(ctx, http.MethodGet, "/repos/"+g.Repo+"/labels/"+url.PathEscape(l.Name), nil, nil)
		if err == nil {
			continue
		}
		if status != http.StatusNotFound {
			return err
		}
		if _, err := g.do(ctx, http.MethodPost, "/repos/"+g.Repo+"/labels",
			map[string]string{"name": l.Name, "color": l.Color, "description": l.Description}, nil); err != nil {
			return err
		}
	}
	return nil
}

func (g *GitHub) Create(ctx context.Context, title, body string, labels []string) (ghIssue, error) {
	var is ghIssue
	_, err := g.do(ctx, http.MethodPost, "/repos/"+g.Repo+"/issues", map[string]any{"title": title, "body": body, "labels": labels}, &is)
	return is, err
}

func (g *GitHub) UpdateBody(ctx context.Context, number int, body string) error {
	_, err := g.do(ctx, http.MethodPatch, fmt.Sprintf("/repos/%s/issues/%d", g.Repo, number), map[string]string{"body": body}, nil)
	return err
}

func (g *GitHub) Comment(ctx context.Context, number int, body string) error {
	_, err := g.do(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/issues/%d/comments", g.Repo, number), map[string]string{"body": body}, nil)
	return err
}

// LastSuccess returns when the given workflow last succeeded on the default branch (zero if never).
func (g *GitHub) LastSuccess(ctx context.Context, workflowFile string) (time.Time, error) {
	var out struct {
		Runs []struct {
			CreatedAt time.Time `json:"created_at"`
		} `json:"workflow_runs"`
	}
	_, err := g.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/actions/workflows/%s/runs?status=success&per_page=1", g.Repo, url.PathEscape(workflowFile)), nil, &out)
	if err != nil || len(out.Runs) == 0 {
		return time.Time{}, err
	}
	return out.Runs[0].CreatedAt, nil
}

// ---- markers and de-duplication ----

var markerRE = regexp.MustCompile(`<!-- upstream-monitor:(id|key|evidence)=([^ ]+) -->`)

// markerSafe keeps marker values parseable: no spaces, no comment terminators.
func markerSafe(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', strings.ContainsRune(":/._~%+=@", r):
			b.WriteRune(r)
		case r == '-':
			if !strings.HasSuffix(b.String(), "-") {
				b.WriteRune(r)
			}
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

type trackedIssue struct {
	Issue    ghIssue
	ID       string
	Keys     map[string]bool
	Evidence string
}

// indexIssues reads the markers of the monitor's own issues.
func indexIssues(issues []ghIssue) (byKey map[string]*trackedIssue, all []*trackedIssue) {
	byKey = map[string]*trackedIssue{}
	for _, is := range issues {
		if is.User.Login != TrustedAuthor || is.User.Type != "Bot" {
			continue
		}
		t := &trackedIssue{Issue: is, Keys: map[string]bool{}}
		for _, m := range markerRE.FindAllStringSubmatch(is.Body, -1) {
			switch m[1] {
			case "id":
				t.ID = m[2]
				t.Keys[m[2]] = true
			case "key":
				t.Keys[m[2]] = true
			case "evidence":
				t.Evidence = m[2]
			}
		}
		if t.ID == "" {
			continue
		}
		all = append(all, t)
		for k := range t.Keys {
			if _, ok := byKey[k]; !ok {
				byKey[k] = t
			}
		}
	}
	return byKey, all
}

// Action is what the monitor did (or, in a dry run, would do) for one finding.
type Action struct {
	Finding *Finding
	Do      string // create, update, comment (closed issue), unchanged, tracked (lines already in other issues), deferred, error
	Issue   *ghIssue
	Err     string
}

// planIssues decides, without side effects, what each issue-worthy finding needs.
func planIssues(findings []*Finding, issues []ghIssue, maxNew int) []Action {
	byKey, _ := indexIssues(issues)
	var acts []Action
	created := 0
	// Sentences claimed by an earlier finding in this run (a GA entry repeating its beta's notes).
	claimed := map[string]*Finding{}
	// Most severe first, so the new-issue limit defers the least important findings.
	ordered := append([]*Finding(nil), findings...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Severity > ordered[j].Severity })
	for _, f := range ordered {
		if !f.NeedsIssue() {
			continue
		}
		if len(f.EvidenceKeys) > 0 {
			var ev, keys []string
			for i, k := range f.EvidenceKeys {
				if _, dup := claimed[k]; !dup {
					ev, keys = append(ev, f.Evidence[i]), append(keys, k)
				}
			}
			if len(ev) == 0 {
				acts = append(acts, Action{Finding: f, Do: "tracked"})
				continue
			}
			f.Evidence, f.EvidenceKeys, f.Keys = ev, keys, keys
			for _, k := range keys {
				claimed[k] = f
			}
		}
		if t, ok := byKey[markerSafe(f.ID)]; ok {
			is := t.Issue
			switch {
			case t.Evidence == markerSafe(f.EvidenceHash()):
				acts = append(acts, Action{Finding: f, Do: "unchanged", Issue: &is})
			case is.State == "closed":
				acts = append(acts, Action{Finding: f, Do: "comment", Issue: &is})
			default:
				acts = append(acts, Action{Finding: f, Do: "update", Issue: &is})
			}
			continue
		}
		// Another issue may already track this finding under an alias (a CVE of a GHSA) or, for changelog
		// entries, track some of its lines (a GA release repeats its beta's notes).
		var other *trackedIssue
		for _, k := range f.Keys {
			if t, ok := byKey[markerSafe(k)]; ok && len(f.EvidenceKeys) == 0 {
				other = t
				break
			}
		}
		if other != nil {
			is := other.Issue
			acts = append(acts, Action{Finding: f, Do: "tracked", Issue: &is})
			continue
		}
		if len(f.EvidenceKeys) > 0 {
			var ev, keys []string
			var firstTracked *ghIssue
			for i, k := range f.EvidenceKeys {
				if t, ok := byKey[markerSafe(k)]; ok {
					if firstTracked == nil {
						is := t.Issue
						firstTracked = &is
					}
					continue
				}
				ev, keys = append(ev, f.Evidence[i]), append(keys, k)
			}
			if len(ev) == 0 {
				acts = append(acts, Action{Finding: f, Do: "tracked", Issue: firstTracked})
				continue
			}
			f.Evidence, f.EvidenceKeys, f.Keys = ev, keys, keys
		}
		if created >= maxNew {
			acts = append(acts, Action{Finding: f, Do: "deferred"})
			continue
		}
		created++
		acts = append(acts, Action{Finding: f, Do: "create"})
	}
	return acts
}

// applyIssues carries out the plan. It stops writing at the first rate-limit answer.
func applyIssues(ctx context.Context, g *GitHub, acts []Action, runURL string, now time.Time) []Action {
	limited := false
	for i := range acts {
		a := &acts[i]
		if limited && (a.Do == "create" || a.Do == "update" || a.Do == "comment") {
			a.Err, a.Do = ErrRateLimited.Error(), "deferred"
			continue
		}
		var err error
		switch a.Do {
		case "create":
			var is ghIssue
			is, err = g.Create(ctx, issueTitle(a.Finding), issueBody(a.Finding, runURL, now), labelsFor(a.Finding.Kind))
			if err == nil {
				a.Issue = &is
			}
		case "update", "comment":
			err = g.Comment(ctx, a.Issue.Number, updateComment(a.Finding, runURL, now))
			if err == nil {
				err = g.UpdateBody(ctx, a.Issue.Number, replaceEvidenceMarker(a.Issue.Body, a.Finding.EvidenceHash()))
			}
		}
		if err != nil {
			if errors.Is(err, ErrRateLimited) {
				limited = true
			}
			a.Err, a.Do = err.Error(), "error"
		}
	}
	return acts
}

func replaceEvidenceMarker(body, hash string) string {
	m := "<!-- upstream-monitor:evidence=" + markerSafe(hash) + " -->"
	re := regexp.MustCompile(`<!-- upstream-monitor:evidence=[^ ]+ -->`)
	if re.MatchString(body) {
		return re.ReplaceAllLiteralString(body, m)
	}
	return body + "\n" + m + "\n"
}
