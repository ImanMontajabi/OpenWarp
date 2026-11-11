package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

const month = 30 * 24 * time.Hour

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func byID(fs []*Finding, id string) *Finding {
	for _, f := range fs {
		if f.ID == id {
			return f
		}
	}
	return nil
}

// ---- upstream release detection ----

func TestChangelogFindsRelevantMacOSChanges(t *testing.T) {
	fs, v, n, err := analyzeChangelog(fixture(t, "changelog.xml"), now, month, "2026.8.2115.0")
	if err != nil || n != 5 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	beta := byID(fs, "cf-changelog:https://developers.cloudflare.com/changelog/post/2026-11-08-warp-macos-beta")
	if beta == nil {
		t.Fatalf("macOS beta not reported: %v", ids(fs))
	}
	ev := strings.Join(beta.Evidence, "\n")
	if !strings.Contains(ev, "MASQUE issue") || !strings.Contains(ev, "local proxy") {
		t.Fatalf("relevant lines missing: %q", ev)
	}
	for _, unrelated := range []string{"MDM", "Settings window"} {
		if strings.Contains(ev, unrelated) {
			t.Fatalf("line about %s (not implemented / not relevant) reported: %q", unrelated, ev)
		}
	}
	// A security line makes it a potential security finding, never "confirmed".
	if beta.Kind != KindSecurity || beta.Severity != SevHigh || beta.Impact != ImpactPotential {
		t.Fatalf("beta classified as %s/%s/%s", beta.Kind, beta.Severity, beta.Impact)
	}
	// The same MASQUE line on Windows is kept, but only for the summary.
	win := byID(fs, "cf-changelog:https://developers.cloudflare.com/changelog/post/2026-11-08-warp-windows-beta")
	if win == nil || win.NeedsIssue() {
		t.Fatalf("Windows entry should be a summary-only finding: %+v", win)
	}
	if strings.Contains(strings.Join(win.Evidence, " "), "Windows Server") {
		t.Fatal("a platform-specific DNS line from Windows was reported")
	}
	// Outside the lookback window: versions still counted, nothing analysed.
	if byID(fs, "cf-changelog:https://developers.cloudflare.com/changelog/post/2026-01-05-warp-macos-ga") != nil {
		t.Fatal("entry older than the lookback analysed")
	}
	// Hotfix of an older train published later must not lower the latest version.
	if v.LatestGA != "2026.8.2200.0" || v.LatestBeta != "2026.9.3000.1" {
		t.Fatalf("versions = %+v", v)
	}
}

func TestBaselineFindingOnlyWhenARelease(t *testing.T) {
	fs, _, _, _ := analyzeChangelog(fixture(t, "changelog.xml"), now, month, "2026.8.2115.0")
	b := byID(fs, "cf-macos-ga-newer-than:2026.8.2115.0")
	if b == nil || !b.NeedsIssue() || !strings.Contains(b.Title, "2026.8.2200.0") {
		t.Fatalf("newer GA not reported: %+v", b)
	}
	// A newer beta alone is not a reason: baseline equal to the latest GA.
	fs, _, _, _ = analyzeChangelog(fixture(t, "changelog.xml"), now, month, "2026.8.2200.0")
	if byID(fs, "cf-macos-ga-newer-than:2026.8.2200.0") != nil {
		t.Fatal("reported a newer client although only a beta is newer")
	}
}

func TestReleaseNotesRepeatedAcrossEntriesAreReportedOnce(t *testing.T) {
	fs, _, _, _ := analyzeChangelog(fixture(t, "changelog.xml"), now, month, "2026.8.2200.0")
	acts := planIssues(mergeFindings(fs), nil, 10)
	var created []*Finding
	for _, a := range acts {
		if a.Do == "create" {
			created = append(created, a.Finding)
		}
	}
	// The GA entry repeats the beta's MASQUE line and has nothing else relevant.
	if len(created) != 1 || !strings.Contains(created[0].ID, "macos-beta") {
		t.Fatalf("created %v", ids(created))
	}
	ga := byID(fs, "cf-changelog:https://developers.cloudflare.com/changelog/post/2026-11-09-warp-macos-ga")
	for _, a := range acts {
		if a.Finding == ga && a.Do != "tracked" {
			t.Fatalf("GA entry: %s, want tracked", a.Do)
		}
	}
}

// ---- advisories ----

func TestAdvisoryClassification(t *testing.T) {
	fs, n, err := analyzeAdvisories(fixture(t, "advisories.json"))
	if err != nil || n != 5 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	cases := map[string]struct {
		impact Impact
		issue  bool
	}{
		"ghsa:GHSA-aaaa-bbbb-cccc": {ImpactNotApplicable, false}, // Windows installer
		"ghsa:GHSA-dddd-eeee-ffff": {ImpactNotApplicable, false}, // Zero Trust feature
		"ghsa:GHSA-gggg-hhhh-jjjj": {ImpactPotential, true},      // macOS, MASQUE
	}
	for id, want := range cases {
		f := byID(fs, id)
		if f == nil {
			t.Fatalf("%s missing", id)
		}
		if f.Impact != want.impact || f.NeedsIssue() != want.issue {
			t.Errorf("%s: impact %s issue %v, want %s %v (%s)", id, f.Impact, f.NeedsIssue(), want.impact, want.issue, f.Reasoning)
		}
		if f.Impact == ImpactConfirmed || f.Severity == SevCritical {
			t.Errorf("%s: an official-client advisory is never confirmed for OpenWarp", id)
		}
	}
	if byID(fs, "ghsa:GHSA-kkkk-mmmm-pppp") != nil || byID(fs, "ghsa:GHSA-qqqq-rrrr-vvvv") != nil {
		t.Fatal("withdrawn or unrelated advisory reported")
	}
	if f := byID(fs, "ghsa:GHSA-gggg-hhhh-jjjj"); len(f.Components) == 0 || f.Components[0].Name != "MASQUE tunnel" {
		t.Fatalf("component not identified: %+v", f.Components)
	}
}

func TestNVDEntryMergesWithItsAdvisory(t *testing.T) {
	adv, _, _ := analyzeAdvisories(fixture(t, "advisories.json"))
	nvd, n, err := analyzeNVD(fixture(t, "nvd.json"))
	if err != nil || n != 2 || len(nvd) != 1 {
		t.Fatalf("n=%d findings=%d err=%v (rejected CVEs must be skipped)", n, len(nvd), err)
	}
	all := mergeFindings(append(adv, nvd...))
	var hits []*Finding
	for _, f := range all {
		if f.ID == "ghsa:GHSA-gggg-hhhh-jjjj" || f.ID == "cve:CVE-2026-0003" {
			hits = append(hits, f)
		}
	}
	if len(hits) != 1 || !strings.Contains(strings.Join(hits[0].Evidence, " "), "nvd.nist.gov") {
		t.Fatalf("GHSA and its CVE should be one finding: %v", ids(hits))
	}
}

func TestBlogClassification(t *testing.T) {
	fs, n, err := analyzeBlog(fixture(t, "blog.xml"), now, month)
	if err != nil || n != 3 || len(fs) != 2 {
		t.Fatalf("n=%d findings=%d err=%v", n, len(fs), err)
	}
	if f := byID(fs, "cf-blog:https://blog.cloudflare.com/warp-masque-everywhere"); f == nil || !f.NeedsIssue() {
		t.Fatalf("protocol announcement not flagged: %+v", f)
	}
	if f := byID(fs, "cf-blog:https://blog.cloudflare.com/unified-data-security"); f == nil || f.NeedsIssue() {
		t.Fatalf("Zero Trust post flagged: %+v", f)
	}
}

// ---- dependencies ----

func TestGovulncheckReachability(t *testing.T) {
	fs, sums, err := analyzeGovulncheck(fixture(t, "govulncheck.json"))
	if err != nil || len(sums) != 2 {
		t.Fatalf("sums=%v err=%v", sums, err)
	}
	q := byID(fs, "govuln:GO-2026-9001")
	if q.Severity != SevCritical || q.Impact != ImpactConfirmed || !q.NeedsIssue() {
		t.Fatalf("called vulnerability: %s %s", q.Severity, q.Impact)
	}
	ev := strings.Join(q.Evidence, " ")
	if !strings.Contains(ev, "fixed in v0.65.1") || !strings.Contains(ev, "CVE-2026-9001") || !strings.Contains(q.Remediation, "go get github.com/quic-go/quic-go@v0.65.1") {
		t.Fatalf("evidence/remediation incomplete: %s / %s", ev, q.Remediation)
	}
	if c := byID(fs, "govuln:GO-2026-9002"); c.Severity != SevLow || c.NeedsIssue() {
		t.Fatalf("module-only vulnerability: %s issue=%v", c.Severity, c.NeedsIssue())
	}
	if _, _, err := analyzeGovulncheck([]byte(`{"progress":{}}`)); err == nil {
		t.Fatal("output without a config message accepted")
	}
	if _, _, err := analyzeGovulncheck([]byte(`not json`)); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestGoListAndGoTest(t *testing.T) {
	ups, err := analyzeGoList(fixture(t, "golist.json"))
	if err != nil || len(ups) != 1 || ups[0].Path != "github.com/quic-go/quic-go" || ups[0].Update != "v0.66.0" {
		t.Fatalf("updates = %+v, %v (only security-sensitive modules)", ups, err)
	}
	pass, err := analyzeGoTest(fixture(t, "gotest-pass.json"))
	if err != nil || !pass.ok() || pass.Passed != 1 || pass.Skipped != 1 {
		t.Fatalf("pass = %+v %v", pass, err)
	}
	fail, _ := analyzeGoTest(fixture(t, "gotest-fail.json"))
	if fail.ok() || fail.Failed != 1 || len(fail.Failures) != 2 {
		t.Fatalf("fail = %+v (a failing test, plus a package failing without a failing test)", fail)
	}
	if _, err := analyzeGoTest(nil); err == nil {
		t.Fatal("empty test output accepted")
	}
}

// ---- fetching: outages, changes, rate limits ----

func testFetcher() *Fetcher {
	f := NewFetcher()
	f.Sleep = func(time.Duration) {}
	return f
}

func TestOutageIsNotAFormatChange(t *testing.T) {
	var hits int
	var slept []time.Duration
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		switch r.URL.Path {
		case "/down":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "/limited":
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
		case "/gone":
			w.WriteHeader(http.StatusNotFound)
		case "/flaky":
			if hits%2 == 1 {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			w.Write([]byte("ok"))
		}
	}))
	defer srv.Close()
	f := testFetcher()
	f.Sleep = func(d time.Duration) { slept = append(slept, d) }
	ctx := context.Background()

	hits = 0
	if _, err := f.Get(ctx, srv.URL+"/down", nil); stateOf(err) != SourceOutage || hits != 3 {
		t.Fatalf("5xx: %v after %d tries", err, hits)
	}
	hits, slept = 0, nil
	if _, err := f.Get(ctx, srv.URL+"/limited", nil); stateOf(err) != SourceOutage || slept[0] != 7*time.Second {
		t.Fatalf("429: %v, slept %v (Retry-After honoured)", err, slept)
	}
	hits = 0
	if _, err := f.Get(ctx, srv.URL+"/gone", nil); stateOf(err) != SourceChanged || hits != 1 {
		t.Fatalf("404: %v after %d tries (no retry)", err, hits)
	}
	hits = 0
	if b, err := f.Get(ctx, srv.URL+"/flaky", nil); err != nil || string(b) != "ok" {
		t.Fatalf("a retry should recover: %v", err)
	}
	f.MaxRetryAfter = time.Second
	slept = nil
	f.Get(ctx, srv.URL+"/limited", nil)
	if slept[0] != time.Second {
		t.Fatalf("Retry-After not capped: %v", slept)
	}
}

func TestInvalidOrIncompleteResponses(t *testing.T) {
	for name, body := range map[string]string{
		"html page":  "<html><body>Maintenance</body></html>",
		"empty feed": `<rss><channel><title>x</title></channel></rss>`,
		"no titles":  `<rss><channel><item><description>x</description></item></channel></rss>`,
		"truncated":  `<rss><channel><item><title>Cloudflare One`,
	} {
		if _, err := parseRSS([]byte(body)); stateOf(err) != SourceChanged {
			t.Errorf("%s: %v, want format changed", name, err)
		}
	}
	if _, _, _, err := analyzeChangelog([]byte(`<rss><channel><item><title>New look</title><link>https://x</link></item></channel></rss>`), now, month, "1.0"); stateOf(err) != SourceChanged {
		t.Errorf("changelog titles without versions: %v", err)
	}
	if _, _, err := analyzeAdvisories([]byte(`{"message":"Not Found"}`)); stateOf(err) != SourceChanged {
		t.Errorf("advisories object: %v", err)
	}
	if _, _, err := analyzeAdvisories([]byte(`[{"summary":"WARP"}]`)); stateOf(err) != SourceChanged {
		t.Errorf("advisory without id: %v", err)
	}
	if _, _, err := analyzeNVD([]byte(`{"vulnerabilities":[]}`)); stateOf(err) != SourceChanged {
		t.Errorf("NVD without totalResults: %v", err)
	}
	f := testFetcher()
	f.MaxBytes = 10
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(make([]byte, 100)) }))
	defer srv.Close()
	if _, err := f.Get(context.Background(), srv.URL, nil); stateOf(err) != SourceChanged {
		t.Errorf("oversized response: %v", err)
	}
}

// ---- identifiers and sanitising ----

func TestStableFindingIdentifiers(t *testing.T) {
	a := canonicalURL("https://Developers.cloudflare.com/changelog/post/x/?utm_source=rss#top")
	b := canonicalURL("https://developers.cloudflare.com/changelog/post/x")
	if a != b {
		t.Fatalf("%q != %q", a, b)
	}
	s1 := classifySentence("Fixed a  MASQUE issue.").Key
	s2 := classifySentence("fixed a MASQUE issue.").Key
	if s1 != s2 {
		t.Fatal("sentence keys depend on case or spacing")
	}
	for _, id := range []string{"cf-changelog:https://x/y--z?q=1 -->", "ghsa:GHSA-aaaa-bbbb-cccc"} {
		m := markerSafe(id)
		if strings.Contains(m, "-->") || strings.Contains(m, " ") || markerSafe(m) != m {
			t.Fatalf("marker value %q not safe/idempotent", m)
		}
	}
	f := &Finding{Severity: SevHigh, Impact: ImpactPotential, Evidence: []string{"a"}}
	h := f.EvidenceHash()
	f.Evidence = []string{"a", "b"}
	if f.EvidenceHash() == h {
		t.Fatal("evidence hash ignores new evidence")
	}
}

func TestUpstreamTextIsDefused(t *testing.T) {
	in := "Thanks @octocat, fixes #12 and GH-4. <!-- upstream-monitor:id=ghsa:X --> <script>x</script>\x07"
	out := sanitize(in, 500)
	for _, bad := range []string{"@octocat", "#12", "GH-4", "<!--", "<script>", "\x07"} {
		if strings.Contains(out, bad) {
			t.Errorf("%q survived: %q", bad, out)
		}
	}
	if safeURL("https://evil.example/x") != "" || safeURL("http://github.com/x") != "" || safeURL("https://u:p@github.com/") != "" {
		t.Fatal("unsafe URL allowed")
	}
	if safeURL("https://developers.cloudflare.com/changelog/") == "" {
		t.Fatal("official URL rejected")
	}
	fs, _, _, _ := analyzeChangelog(fixture(t, "changelog.xml"), now, month, "2026.8.2200.0")
	body := issueBody(byID(fs, "cf-changelog:https://developers.cloudflare.com/changelog/post/2026-11-08-warp-macos-beta"), "https://github.com/o/r/actions/runs/1", now)
	if strings.Contains(body, "@someone") || strings.Contains(body, "see #12") {
		t.Fatalf("mention or issue reference in the issue body:\n%s", body)
	}
	if n := len(markerRE.FindAllString(body, -1)); n < 3 {
		t.Fatalf("markers missing (%d)", n)
	}
}

func TestTokenOnlyGoesToTheGitHubAPI(t *testing.T) {
	if h := githubHeaders("https://api.github.com/repos/cloudflare/advisories/security-advisories", "tok"); h["Authorization"] != "Bearer tok" {
		t.Fatal("GitHub API request not authenticated")
	}
	for _, u := range []string{"https://api.github.com.evil.example/x", "http://api.github.com/x", "https://services.nvd.nist.gov/x"} {
		if h := githubHeaders(u, "tok"); h["Authorization"] != "" {
			t.Fatalf("token sent to %s", u)
		}
	}
}

// ---- GitHub issues: creation, de-duplication, updates, rate limits ----

type fakeGitHub struct {
	mu        sync.Mutex
	issues    []map[string]any
	comments  map[int][]string
	labels    map[string]bool
	writes    int
	limited   bool
	listCalls int
}

func newFakeGitHub(t *testing.T) (*fakeGitHub, *GitHub) {
	fg := &fakeGitHub{comments: map[int][]string{}, labels: map[string]bool{"security": true, "dependencies": true}}
	issueRE := regexp.MustCompile(`^/repos/o/r/issues/(\d+)(/comments)?$`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fg.mu.Lock()
		defer fg.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(401)
			return
		}
		if fg.limited && r.Method != http.MethodGet {
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.WriteHeader(403)
			return
		}
		var in map[string]any
		json.NewDecoder(r.Body).Decode(&in)
		switch {
		case r.Method == "GET" && r.URL.Path == "/repos/o/r/issues":
			fg.listCalls++
			if r.URL.Query().Get("labels") != issueLabel || r.URL.Query().Get("state") != "all" {
				w.WriteHeader(400)
				return
			}
			json.NewEncoder(w).Encode(fg.issues)
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/repos/o/r/labels/"):
			if !fg.labels[strings.TrimPrefix(r.URL.Path, "/repos/o/r/labels/")] {
				w.WriteHeader(404)
			}
		case r.Method == "POST" && r.URL.Path == "/repos/o/r/labels":
			fg.writes++
			fg.labels[in["name"].(string)] = true
		case r.Method == "POST" && r.URL.Path == "/repos/o/r/issues":
			fg.writes++
			n := len(fg.issues) + 1
			is := map[string]any{"number": n, "title": in["title"], "body": in["body"], "state": "open",
				"html_url": fmt.Sprintf("https://github.com/o/r/issues/%d", n),
				"user":     map[string]any{"login": TrustedAuthor, "type": "Bot"}, "labels": labelObjs(in["labels"])}
			fg.issues = append(fg.issues, is)
			json.NewEncoder(w).Encode(is)
		case issueRE.MatchString(r.URL.Path):
			m := issueRE.FindStringSubmatch(r.URL.Path)
			n, _ := strconv.Atoi(m[1])
			fg.writes++
			if m[2] != "" {
				fg.comments[n] = append(fg.comments[n], in["body"].(string))
			} else if r.Method == "PATCH" {
				fg.issues[n-1]["body"] = in["body"]
			}
		case strings.Contains(r.URL.Path, "/actions/workflows/"):
			w.Write([]byte(`{"workflow_runs":[{"created_at":"2026-11-09T06:00:00Z"}]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	return fg, &GitHub{API: srv.URL, Repo: "o/r", Token: "test-token", HTTP: srv.Client()}
}

func labelObjs(v any) []map[string]string {
	var out []map[string]string
	if l, ok := v.([]any); ok {
		for _, x := range l {
			out = append(out, map[string]string{"name": x.(string)})
		}
	}
	return out
}

func issueWorthy() []*Finding {
	return []*Finding{{
		ID: "ghsa:GHSA-gggg-hhhh-jjjj", Keys: []string{"cve:CVE-2026-0003"}, Kind: KindSecurity, Title: "Advisory",
		Source: "cf-advisories", URL: "https://github.com/cloudflare/advisories/security/advisories/GHSA-gggg-hhhh-jjjj",
		Severity: SevHigh, Impact: ImpactPotential, Confidence: "medium", Evidence: []string{"first evidence"},
		Components: componentsNamed("MASQUE tunnel"),
	}}
}

func TestIssuesAreCreatedOnceAndUpdatedOnNewEvidence(t *testing.T) {
	fg, gh := newFakeGitHub(t)
	ctx := context.Background()
	run := func(fs []*Finding) []Action {
		issues, err := gh.MonitorIssues(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := gh.EnsureLabels(ctx); err != nil {
			t.Fatal(err)
		}
		return applyIssues(ctx, gh, planIssues(fs, issues, 5), "https://github.com/o/r/actions/runs/1", now)
	}

	acts := run(issueWorthy())
	if len(acts) != 1 || acts[0].Do != "create" || len(fg.issues) != 1 {
		t.Fatalf("first run: %+v", acts)
	}
	body := fg.issues[0]["body"].(string)
	for _, want := range []string{"upstream-monitor:id=ghsa:GHSA-gggg-hhhh-jjjj", "upstream-monitor:key=cve:CVE-2026-0003",
		"Potentially affected", "internal/tunnel/masque.go", "TestMasqueConnectIP", "Detected | 2026-11-10",
		"https://github.com/o/r/blob/main/docs/maintenance-monitoring.md"} {
		if !strings.Contains(body, want) {
			t.Errorf("issue body lacks %q", want)
		}
	}
	for _, l := range []string{issueLabel, "security", "needs-investigation"} {
		if !fg.labels[l] {
			t.Errorf("label %s not created", l)
		}
	}

	writes := fg.writes
	if acts := run(issueWorthy()); acts[0].Do != "unchanged" || fg.writes != writes {
		t.Fatalf("second identical run wrote: %+v (%d writes)", acts, fg.writes-writes)
	}

	// The same finding under its alias (the CVE from the NVD) is not a new issue.
	alias := issueWorthy()
	alias[0].ID, alias[0].Keys = "cve:CVE-2026-0003", nil
	if acts := run(alias); (acts[0].Do != "tracked" && acts[0].Do != "unchanged") || len(fg.issues) != 1 {
		t.Fatalf("alias created a duplicate: %+v", acts)
	}

	more := issueWorthy()
	more[0].Evidence = append(more[0].Evidence, "second evidence")
	if acts := run(more); acts[0].Do != "update" || len(fg.comments[1]) != 1 {
		t.Fatalf("new evidence: %+v", acts)
	}
	if !strings.Contains(fg.comments[1][0], "second evidence") || !strings.Contains(fg.issues[0]["body"].(string), more[0].EvidenceHash()) {
		t.Fatal("update comment or evidence marker missing")
	}
	if acts := run(more); acts[0].Do != "unchanged" {
		t.Fatalf("after the update: %+v", acts)
	}

	// A closed issue gets a comment, is never reopened, and is never duplicated.
	fg.issues[0]["state"] = "closed"
	more[0].Evidence = append(more[0].Evidence, "third evidence")
	if acts := run(more); acts[0].Do != "comment" || fg.issues[0]["state"] != "closed" || len(fg.issues) != 1 {
		t.Fatalf("closed issue: %+v", acts)
	}
}

func TestForgedMarkersFromOtherAuthorsAreIgnored(t *testing.T) {
	fg, gh := newFakeGitHub(t)
	fg.issues = append(fg.issues, map[string]any{
		"number": 1, "title": "spam", "state": "open", "html_url": "https://github.com/o/r/issues/1",
		"body": "<!-- upstream-monitor:id=ghsa:GHSA-gggg-hhhh-jjjj -->\n<!-- upstream-monitor:evidence=x -->",
		"user": map[string]any{"login": "stranger", "type": "User"},
	})
	issues, _ := gh.MonitorIssues(context.Background())
	if acts := planIssues(issueWorthy(), issues, 5); acts[0].Do != "create" {
		t.Fatalf("a stranger's marker suppressed the alert: %+v", acts)
	}
}

func TestNewIssueLimitAndRateLimit(t *testing.T) {
	var fs []*Finding
	for i := 0; i < 4; i++ {
		f := issueWorthy()[0]
		f.ID, f.Keys = fmt.Sprintf("ghsa:GHSA-%d", i), nil
		fs = append(fs, f)
	}
	acts := planIssues(fs, nil, 2)
	if acts[0].Do != "create" || acts[1].Do != "create" || acts[2].Do != "deferred" || acts[3].Do != "deferred" {
		t.Fatalf("limit not applied: %v", dos(acts))
	}
	// The limit never defers a more severe finding in favour of a less severe one.
	low := issueWorthy()[0]
	low.ID, low.Keys, low.Severity, low.Impact = "cf-blog:x", nil, SevMedium, ImpactInsufficient
	crit := issueWorthy()[0]
	crit.ID, crit.Keys, crit.Severity, crit.Impact = "govuln:GO-1", nil, SevCritical, ImpactConfirmed
	acts = planIssues([]*Finding{low, crit}, nil, 1)
	if acts[0].Finding != crit || acts[0].Do != "create" || acts[1].Do != "deferred" {
		t.Fatalf("critical finding deferred: %v %v", dos(acts), acts[0].Finding.ID)
	}

	fg, gh := newFakeGitHub(t)
	fg.limited = true
	acts = applyIssues(context.Background(), gh, planIssues(fs, nil, 4), "u", now)
	if acts[0].Do != "error" || !strings.Contains(acts[0].Err, "rate limit") {
		t.Fatalf("rate limit not detected: %+v", acts[0])
	}
	for _, a := range acts[1:] {
		if a.Do != "deferred" {
			t.Fatalf("kept writing after a rate limit: %v", dos(acts))
		}
	}
	if fg.writes != 0 {
		t.Fatalf("%d writes while rate-limited", fg.writes)
	}
}

// ---- the whole run ----

func upstream(t *testing.T, changelogStatus int) URLs {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/changelog":
			if changelogStatus != 200 {
				w.WriteHeader(changelogStatus)
				return
			}
			w.Write(fixture(t, "changelog.xml"))
		case "/blog":
			w.Write(fixture(t, "blog.xml"))
		case "/advisories":
			if r.Header.Get("Authorization") != "" {
				t.Error("token sent to a non-GitHub host")
			}
			w.Write(fixture(t, "advisories.json"))
		case "/nvd":
			if r.URL.Query().Get("lastModStartDate") == "" || r.URL.Query().Get("lastModEndDate") == "" {
				w.WriteHeader(400)
				return
			}
			w.Write(fixture(t, "nvd.json"))
		}
	}))
	t.Cleanup(srv.Close)
	return URLs{Changelog: srv.URL + "/changelog", Blog: srv.URL + "/blog", Advisories: srv.URL + "/advisories", NVD: srv.URL + "/nvd?keywordSearch=Cloudflare%20WARP"}
}

func runConfig(t *testing.T, urls URLs, gh *GitHub) Config {
	return Config{
		URLs: urls, Baseline: "2026.8.2115.0", Lookback: month, Now: now, MaxNewIssues: 5,
		RunURL: "https://github.com/o/r/actions/runs/1", Fetcher: testFetcher(), GitHub: gh,
		GovulnPath: filepath.Join("testdata", "govulncheck.json"), GoListPath: filepath.Join("testdata", "golist.json"),
		GoTestPath: filepath.Join("testdata", "gotest-pass.json"), WorkflowFile: "upstream-monitor.yml",
	}
}

func TestRunEndToEnd(t *testing.T) {
	fg, gh := newFakeGitHub(t)
	c := runConfig(t, upstream(t, 200), gh)
	c.MaxNewIssues = 20
	r := Run(context.Background(), c)
	if len(r.failedSources()) != 0 {
		t.Fatalf("sources failed: %+v", r.Sources)
	}
	if c.Fetcher.Requests != 4 {
		t.Fatalf("%d upstream requests, want one per source", c.Fetcher.Requests)
	}
	created := 0
	for _, a := range r.Actions {
		if a.Do == "create" {
			created++
		}
	}
	if created == 0 || created != len(fg.issues) {
		t.Fatalf("created %d issues, fake has %d", created, len(fg.issues))
	}
	if r.ExitCode() != 1 {
		t.Fatal("a reachable (called) vulnerability must fail the run")
	}
	md := r.Markdown()
	for _, want := range []string{"### Sources", "Studied: `2026.8.2115.0`", "GO-2026-9001", "github.com/quic-go/quic-go", "Last successful run",
		"Offline compatibility tests", "1 passed", "Unresolved security findings", "Recommended next actions", "critical finding"} {
		if !strings.Contains(md, want) {
			t.Errorf("summary lacks %q", want)
		}
	}
	calls := gh.Calls
	if calls > 2+len(monitorLabels)*2+created {
		t.Fatalf("%d GitHub API calls for %d issues", calls, created)
	}

	// The next day nothing is new: no writes, no duplicates.
	writes := fg.writes
	c2 := runConfig(t, upstream(t, 200), gh)
	c2.MaxNewIssues = 20
	r2 := Run(context.Background(), c2)
	for _, a := range r2.Actions {
		if a.Do == "create" || a.Do == "update" {
			t.Fatalf("second run: %s %s", a.Do, a.Finding.ID)
		}
	}
	if fg.writes != writes {
		t.Fatalf("second run wrote %d times", fg.writes-writes)
	}
}

func TestRunSourceOutageAndFormatChange(t *testing.T) {
	_, gh := newFakeGitHub(t)
	r := Run(context.Background(), runConfig(t, upstream(t, http.StatusServiceUnavailable), gh))
	if r.Sources[0].State != SourceOutage {
		t.Fatalf("changelog state %s", r.Sources[0].State)
	}
	for _, f := range r.Findings {
		if f.Kind == KindMonitor {
			t.Fatal("an outage opened a 'source changed' issue")
		}
	}
	if !strings.Contains(r.Markdown(), "unavailable") {
		t.Fatal("outage not in the summary")
	}

	r = Run(context.Background(), runConfig(t, upstream(t, http.StatusNotFound), gh))
	if r.Sources[0].State != SourceChanged || byID(r.Findings, "source-changed:cf-changelog") == nil {
		t.Fatalf("a moved source must be reported: %+v", r.Sources[0])
	}

	// Every source down: the run fails so the maintainer hears about it.
	dead := URLs{Changelog: "http://127.0.0.1:1/x", Blog: "http://127.0.0.1:1/x", Advisories: "http://127.0.0.1:1/x", NVD: "http://127.0.0.1:1/x"}
	c := runConfig(t, dead, nil)
	c.GovulnPath, c.GoTestPath = "", filepath.Join("testdata", "gotest-pass.json")
	if r := Run(context.Background(), c); r.ExitCode() != 1 {
		t.Fatal("all sources down should fail the run")
	}
}

func TestRunWithoutGitHubIsADryRun(t *testing.T) {
	c := runConfig(t, upstream(t, 200), nil)
	c.DryRun = true
	r := Run(context.Background(), c)
	md := r.Markdown()
	if !strings.Contains(md, "dry run") || !strings.Contains(md, "would open") {
		t.Fatalf("dry-run summary:\n%s", md)
	}
	c.GovulnPath = ""
	if md := Run(context.Background(), c).Markdown(); !strings.Contains(md, "not run") {
		t.Fatal("a skipped govulncheck must not read as 'no vulnerabilities'")
	}
}

func TestFailingCompatibilityTestsFailTheRun(t *testing.T) {
	c := runConfig(t, upstream(t, 200), nil)
	c.GovulnPath, c.GoTestPath = "", filepath.Join("testdata", "gotest-fail.json")
	r := Run(context.Background(), c)
	if r.ExitCode() != 1 || !strings.Contains(r.Markdown(), "TestMasqueCompatRefusedConnect") {
		t.Fatal("failing offline tests must fail the run and be listed")
	}
}

func ids(fs []*Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

func dos(acts []Action) []string {
	var out []string
	for _, a := range acts {
		out = append(out, a.Do)
	}
	return out
}

func TestMissingTestOutputFailsTheRun(t *testing.T) {
	c := runConfig(t, upstream(t, 200), nil)
	c.GovulnPath, c.GoTestPath = "", filepath.Join(t.TempDir(), "absent.json")
	r := Run(context.Background(), c)
	if r.ExitCode() != 1 || !strings.Contains(r.Markdown(), "no readable output") {
		t.Fatal("expected test output that is missing must fail the run, not pass silently")
	}
}
