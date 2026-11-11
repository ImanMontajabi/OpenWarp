// Command upstream-monitor watches the official sources OpenWarp depends on (Cloudflare's client changelog,
// security advisories, the NVD, the WARP blog) and OpenWarp's Go dependencies, classifies what it finds
// against OpenWarp's components, and opens or updates de-duplicated GitHub issues for what needs a
// maintainer. It only reads upstream sources and reports: it never changes code, settings or networking.
//
// It runs in GitHub Actions (.github/workflows/upstream-monitor.yml); see docs/maintenance-monitoring.md.
//
//	go run ./tools/upstream-monitor -dry-run                        # local, read-only
//	go run ./tools/upstream-monitor -govulncheck vuln.json -gotest test.json -golist mods.json
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ImanMontajabi/OpenWarp/internal/api"
)

// URLs of the monitored sources (overridden in tests).
type URLs struct {
	Changelog, Blog, Advisories, NVD string
}

var DefaultURLs = URLs{
	// Official Cloudflare One Client (WARP) release notes, RSS. Every platform; entries name the version.
	Changelog: "https://developers.cloudflare.com/changelog/rss/cloudflare-one-client.xml",
	// Cloudflare blog posts tagged WARP, RSS.
	Blog: "https://blog.cloudflare.com/tag/warp/rss/",
	// Cloudflare's published security advisories (GitHub repository advisories of cloudflare/advisories).
	Advisories: "https://api.github.com/repos/cloudflare/advisories/security-advisories?per_page=100&state=published",
	// NVD CVE API 2.0; the date window is added per run.
	NVD: "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Cloudflare%20WARP",
}

type Config struct {
	URLs          URLs
	Baseline      string
	Lookback      time.Duration
	Now           time.Time
	Token         string // GitHub token (issues and, if set, authenticated advisory reads)
	DryRun        bool
	MaxNewIssues  int
	RunURL        string
	GovulnPath    string
	GoListPath    string
	GoTestPath    string
	WorkflowFile  string
	Fetcher       *Fetcher
	GitHub        *GitHub
	SkipLastCheck bool
}

func main() {
	var c Config
	var summary, jsonOut string
	c.URLs = DefaultURLs
	c.Baseline = strings.TrimPrefix(api.MacClientVersion, "m-")
	flag.BoolVar(&c.DryRun, "dry-run", false, "read only: plan issues but write nothing to GitHub")
	flag.IntVar(&c.MaxNewIssues, "max-new-issues", 5, "most issues to open in one run (the rest wait for the next run)")
	flag.DurationVar(&c.Lookback, "lookback", 30*24*time.Hour, "how far back changelog and blog entries are analysed")
	flag.StringVar(&c.GovulnPath, "govulncheck", "", "govulncheck -format json output")
	flag.StringVar(&c.GoListPath, "golist", "", "go list -m -u -json all output")
	flag.StringVar(&c.GoTestPath, "gotest", "", "go test -json output of the offline compatibility tests")
	flag.StringVar(&summary, "summary", os.Getenv("GITHUB_STEP_SUMMARY"), "append the Markdown report to this file")
	flag.StringVar(&jsonOut, "json", "", "write the full report as JSON to this file")
	flag.Parse()

	repo := os.Getenv("GITHUB_REPOSITORY")
	c.Token = os.Getenv("GITHUB_TOKEN")
	c.Now = time.Now().UTC()
	c.WorkflowFile = "upstream-monitor.yml"
	c.RunURL = "https://github.com/" + repo + "/actions"
	if id := os.Getenv("GITHUB_RUN_ID"); id != "" && repo != "" {
		c.RunURL = fmt.Sprintf("%s/%s/actions/runs/%s", firstNonEmpty(os.Getenv("GITHUB_SERVER_URL"), "https://github.com"), repo, id)
	}
	c.Fetcher = NewFetcher()
	if repo != "" && c.Token != "" {
		c.GitHub = &GitHub{API: firstNonEmpty(os.Getenv("GITHUB_API_URL"), "https://api.github.com"), Repo: repo, Token: c.Token,
			HTTP: &http.Client{Timeout: 30 * time.Second}}
	} else {
		c.DryRun = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	r := Run(ctx, c)

	md := r.Markdown()
	if summary != "" {
		if f, err := os.OpenFile(summary, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
			f.WriteString(md)
			f.Close()
		}
	} else {
		fmt.Println(md)
	}
	if jsonOut != "" {
		if b, err := json.MarshalIndent(r, "", "  "); err == nil {
			os.WriteFile(jsonOut, b, 0o644)
		}
	}
	for _, s := range r.failedSources() {
		fmt.Printf("::warning::%s: %s (%s)\n", s.Name, s.State, s.Note)
	}
	os.Exit(r.ExitCode())
}

// ExitCode: failure for what a maintainer must act on now (a reachable vulnerability, failing offline
// tests, or no source reachable at all). A partial source outage is a warning, not a failure.
func (r *Report) ExitCode() int {
	if len(r.critical()) > 0 || (r.Tests != nil && !r.Tests.ok()) || (r.TestsExpected && r.Tests == nil) {
		return 1
	}
	if len(r.Sources) > 0 && len(r.failedSources()) == len(r.Sources) {
		return 1
	}
	return 0
}

// Run checks every source and dependency input, then plans (and unless DryRun, applies) the issues.
func Run(ctx context.Context, c Config) *Report {
	r := &Report{Started: c.Now, DryRun: c.DryRun, Versions: Versions{Baseline: c.Baseline}}
	var findings []*Finding

	source := func(id, name, rawURL string, headers map[string]string, analyze func([]byte) ([]*Finding, int, error)) {
		res := SourceResult{ID: id, Name: name, URL: rawURL, State: SourceOK}
		body, err := c.Fetcher.Get(ctx, rawURL, headers)
		var fs []*Finding
		if err == nil {
			fs, res.Items, err = analyze(body)
		}
		if err != nil {
			res.State, res.Note = stateOf(err), err.Error()
			if res.State == SourceChanged {
				findings = append(findings, sourceChangedFinding(res, err))
			}
		}
		findings = append(findings, fs...)
		r.Sources = append(r.Sources, res)
	}

	source("cf-changelog", "Cloudflare One Client changelog", c.URLs.Changelog, nil, func(b []byte) ([]*Finding, int, error) {
		fs, v, n, err := analyzeChangelog(b, c.Now, c.Lookback, c.Baseline)
		if v.LatestGA != "" || v.LatestBeta != "" {
			r.Versions = v
		}
		return fs, n, err
	})
	source("cf-advisories", "Cloudflare security advisories", c.URLs.Advisories, githubHeaders(c.URLs.Advisories, c.Token), analyzeAdvisories)
	source("nvd", "NVD (CVE API, 'Cloudflare WARP')", nvdURL(c.URLs.NVD, c.Now, c.Lookback), nil, analyzeNVD)
	source("cf-blog", "Cloudflare blog (WARP tag)", c.URLs.Blog, nil, func(b []byte) ([]*Finding, int, error) {
		return analyzeBlog(b, c.Now, c.Lookback)
	})

	if c.GovulnPath != "" {
		if data, err := os.ReadFile(c.GovulnPath); err != nil {
			r.Problems = append(r.Problems, "govulncheck output: "+err.Error())
		} else if fs, sums, err := analyzeGovulncheck(data); err != nil {
			r.Problems = append(r.Problems, err.Error())
		} else {
			findings, r.Vulns, r.VulnsChecked = append(findings, fs...), sums, true
		}
	}
	if c.GoListPath != "" {
		if data, err := os.ReadFile(c.GoListPath); err != nil {
			r.Problems = append(r.Problems, "go list output: "+err.Error())
		} else if ups, err := analyzeGoList(data); err != nil {
			r.Problems = append(r.Problems, err.Error())
		} else {
			r.Updates = ups
		}
	}
	if c.GoTestPath != "" {
		r.TestsExpected = true
		if data, err := os.ReadFile(c.GoTestPath); err != nil {
			r.TestsErr = err.Error()
		} else if tr, err := analyzeGoTest(data); err != nil {
			r.TestsErr = err.Error()
		} else {
			r.Tests = &tr
		}
	} else {
		r.TestsErr = "no go test output given"
	}

	r.Findings = mergeFindings(findings)
	if c.GitHub == nil {
		r.Actions = planIssues(r.Findings, nil, c.MaxNewIssues)
		r.Problems = append(r.Problems, "no GitHub repository or token: issues were planned without checking existing ones")
		return r
	}
	issues, err := c.GitHub.MonitorIssues(ctx)
	if err != nil {
		// Without the existing issues there is no de-duplication: write nothing.
		r.Problems = append(r.Problems, "listing monitor issues failed, so no issues were written: "+err.Error())
		r.DryRun = true
		r.Actions = planIssues(r.Findings, nil, c.MaxNewIssues)
		return r
	}
	r.Actions = planIssues(r.Findings, issues, c.MaxNewIssues)
	if !r.DryRun {
		if err := c.GitHub.EnsureLabels(ctx); err != nil {
			r.Problems = append(r.Problems, "creating labels failed, so no issues were written: "+err.Error())
			r.DryRun = true
		} else {
			r.Actions = applyIssues(ctx, c.GitHub, r.Actions, c.RunURL, c.Now)
		}
	}
	_, tracked := indexIssues(issues)
	for _, t := range tracked {
		if t.Issue.State == "open" && hasLabel(t.Issue, "security") {
			r.OpenSec = append(r.OpenSec, t.Issue)
		}
	}
	for _, a := range r.Actions {
		if a.Do == "create" && a.Issue != nil && a.Issue.Number > 0 && a.Finding.Kind != KindCompatibility && a.Finding.Kind != KindMonitor {
			r.OpenSec = append(r.OpenSec, *a.Issue)
		}
	}
	if !c.SkipLastCheck {
		if t, err := c.GitHub.LastSuccess(ctx, c.WorkflowFile); err == nil {
			r.LastSuccess = t
		}
	}
	return r
}

func hasLabel(is ghIssue, name string) bool {
	for _, l := range is.Labels {
		if l.Name == name {
			return true
		}
	}
	return false
}

// githubHeaders authenticates requests to the GitHub API only (never sends the token anywhere else).
func githubHeaders(rawURL, token string) map[string]string {
	h := map[string]string{"Accept": "application/vnd.github+json"}
	if u, err := url.Parse(rawURL); err == nil && u.Scheme == "https" && u.Host == "api.github.com" && token != "" {
		h["Authorization"] = "Bearer " + token
	}
	return h
}

func nvdURL(base string, now time.Time, lookback time.Duration) string {
	// The NVD allows at most 120 days per query.
	if lookback > 120*24*time.Hour {
		lookback = 120 * 24 * time.Hour
	}
	const layout = "2006-01-02T15:04:05.000Z"
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + "lastModStartDate=" + now.Add(-lookback).UTC().Format(layout) + "&lastModEndDate=" + now.UTC().Format(layout)
}

func sourceChangedFinding(s SourceResult, err error) *Finding {
	var fe *FetchError
	status := 0
	if errors.As(err, &fe) {
		status = fe.Status
	}
	return &Finding{
		ID:         "source-changed:" + s.ID,
		Kind:       KindMonitor,
		Title:      "Upstream monitor: the source \"" + s.Name + "\" changed and is no longer understood",
		Source:     s.ID,
		URL:        s.URL,
		Severity:   SevMedium,
		Impact:     ImpactInsufficient,
		Confidence: "high",
		// Stable evidence (no error details that vary per run), so the issue is not updated daily.
		Evidence:  []string{fmt.Sprintf("Source %s answered with a format the monitor cannot read (HTTP status %d).", s.ID, status)},
		Reasoning: "Until the monitor is updated, changes published through this source go unnoticed.",
		Investigate: []string{
			"Open the source URL and check whether it moved or changed format.",
			"Update tools/upstream-monitor (parser and fixture) in a pull request.",
		},
	}
}

// MarshalText makes the JSON report readable.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }
