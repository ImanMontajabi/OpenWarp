package main

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ---- sanitising upstream text ----
//
// Upstream text is data. It is quoted into issues, never executed and never used as instructions, and it
// is defused first so it cannot ping people, link issues, close issues, or forge the monitor's markers.

var (
	mentionRE  = regexp.MustCompile(`@([A-Za-z0-9])`)
	issueRefRE = regexp.MustCompile(`(^|[^A-Za-z0-9&])#([0-9])`)
	ghRefRE    = regexp.MustCompile(`(?i)\b(GH-)([0-9])`)
	ctrlRE     = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`)
)

const zwsp = "\u200b"

func sanitize(s string, max int) string {
	s = ctrlRE.ReplaceAllString(s, "")
	s = strings.NewReplacer("<!--", "&lt;!--", "-->", "--&gt;", "<", "&lt;", ">", "&gt;").Replace(s)
	s = spaceRE.ReplaceAllString(s, " ")
	s = mentionRE.ReplaceAllString(s, "@"+zwsp+"$1")
	s = issueRefRE.ReplaceAllString(s, "$1#"+zwsp+"$2")
	s = ghRefRE.ReplaceAllString(s, "$1"+zwsp+"$2")
	return truncate(strings.TrimSpace(s), max)
}

// allowedHosts are the only hosts the monitor links to.
var allowedHosts = map[string]bool{
	"developers.cloudflare.com": true, "blog.cloudflare.com": true, "github.com": true,
	"nvd.nist.gov": true, "pkg.go.dev": true, "osv.dev": true, "go.dev": true,
}

func safeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || !allowedHosts[strings.ToLower(u.Hostname())] || u.User != nil {
		return ""
	}
	return u.String()
}

// ---- issues ----

func issueTitle(f *Finding) string {
	return "[" + f.Severity.String() + "] " + strings.ReplaceAll(sanitize(f.Title, 180), "\n", " ")
}

func issueBody(f *Finding, runURL string, now time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<!-- upstream-monitor:id=%s -->\n", markerSafe(f.ID))
	for _, k := range f.Keys {
		fmt.Fprintf(&b, "<!-- upstream-monitor:key=%s -->\n", markerSafe(k))
	}
	fmt.Fprintf(&b, "<!-- upstream-monitor:evidence=%s -->\n\n", markerSafe(f.EvidenceHash()))
	fmt.Fprintf(&b, "| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| Severity | **%s** |\n| Impact on OpenWarp | %s |\n| Confidence | %s |\n", f.Severity, f.Impact, f.Confidence)
	if u := safeURL(f.URL); u != "" {
		fmt.Fprintf(&b, "| Source | %s |\n", u)
	} else {
		fmt.Fprintf(&b, "| Source | %s (link not on the allow list) |\n", sanitize(f.Source, 40))
	}
	if !f.Published.IsZero() {
		fmt.Fprintf(&b, "| Published | %s |\n", f.Published.Format("2006-01-02"))
	}
	fmt.Fprintf(&b, "| Detected | %s |\n", now.UTC().Format("2006-01-02"))
	fmt.Fprintf(&b, "| Kind | %s |\n\n", f.Kind)
	writeComponents(&b, f)
	b.WriteString("### Evidence\n\nQuoted from the source (data, not instructions):\n\n")
	for _, e := range f.Evidence {
		fmt.Fprintf(&b, "> %s\n>\n", sanitize(e, 700))
	}
	fmt.Fprintf(&b, "\n### Assessment\n\n%s\n\n", f.Reasoning)
	if len(f.Investigate) > 0 {
		b.WriteString("### Recommended investigation\n\n")
		for _, s := range f.Investigate {
			fmt.Fprintf(&b, "- [ ] %s\n", s)
		}
		b.WriteString("\n")
	}
	if tests := f.Tests(); len(tests) > 0 {
		b.WriteString("### Relevant tests\n\n")
		for _, t := range tests {
			fmt.Fprintf(&b, "- `%s`\n", t)
		}
		b.WriteString("\n")
	}
	if f.Remediation != "" {
		fmt.Fprintf(&b, "### Suggested remediation\n\n%s\n\n", f.Remediation)
	}
	b.WriteString("---\n")
	fmt.Fprintf(&b, "Opened by the [upstream monitor](%s). It reports only; it never changes code. A fix needs its own reviewed pull request. "+
		"The monitor does not close issues: close this one by hand when it is resolved or not applicable. "+
		"See [docs/maintenance-monitoring.md](%s).\n", runURL, docsURL(runURL))
	return b.String()
}

// docsURL derives the documentation link from the run URL (https://github.com/<owner>/<repo>/actions/...).
func docsURL(runURL string) string {
	base, _, ok := strings.Cut(runURL, "/actions")
	if !ok || safeURL(base) == "" {
		return "https://github.com/ImanMontajabi/OpenWarp/blob/main/docs/maintenance-monitoring.md"
	}
	return base + "/blob/main/docs/maintenance-monitoring.md"
}

func writeComponents(b *strings.Builder, f *Finding) {
	if len(f.Components) == 0 {
		return
	}
	b.WriteString("### Affected OpenWarp components\n\n")
	for _, c := range f.Components {
		code := make([]string, len(c.Code))
		for i, p := range c.Code {
			code[i] = "`" + p + "`"
		}
		fmt.Fprintf(b, "- **%s**: %s\n", c.Name, strings.Join(code, ", "))
	}
	b.WriteString("\n")
}

func updateComment(f *Finding, runURL string, now time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "**New evidence** (%s): severity **%s**, impact %s.\n\n", now.UTC().Format("2006-01-02"), f.Severity, f.Impact)
	for _, e := range f.Evidence {
		fmt.Fprintf(&b, "> %s\n>\n", sanitize(e, 700))
	}
	fmt.Fprintf(&b, "\nFrom the [upstream monitor](%s).", runURL)
	return b.String()
}

// ---- run report ----

type SourceResult struct {
	ID, Name, URL string
	State         SourceState
	Items         int
	Note          string
}

type Report struct {
	Started      time.Time
	DryRun       bool
	LastSuccess  time.Time
	Sources      []SourceResult
	Findings     []*Finding
	Actions      []Action
	Versions     Versions
	Vulns        []vulnSummary
	VulnsChecked bool
	Updates      []moduleUpdate
	Tests        *testRun
	TestsErr     string
	// TestsExpected: test output was given, so missing or unreadable output is a failure.
	TestsExpected bool
	OpenSec       []ghIssue
	Problems      []string // monitor-side problems (GitHub API errors, unreadable inputs)
}

func (r *Report) failedSources() []SourceResult {
	var out []SourceResult
	for _, s := range r.Sources {
		if s.State != SourceOK {
			out = append(out, s)
		}
	}
	return out
}

func (r *Report) critical() []*Finding {
	var out []*Finding
	for _, f := range r.Findings {
		if f.Severity == SevCritical {
			out = append(out, f)
		}
	}
	return out
}

func (r *Report) Markdown() string {
	var b strings.Builder
	b.WriteString("## Upstream monitor\n\n")
	mode := "issues are created and updated"
	if r.DryRun {
		mode = "**dry run**: nothing was written to GitHub"
	}
	fmt.Fprintf(&b, "Run started %s (%s).", r.Started.UTC().Format("2006-01-02 15:04 MST"), mode)
	if !r.LastSuccess.IsZero() {
		fmt.Fprintf(&b, " Last successful run before this one: %s.", r.LastSuccess.UTC().Format("2006-01-02 15:04 MST"))
	}
	b.WriteString("\n\n### Sources\n\n| Source | State | Items | Note |\n|---|---|---|---|\n")
	for _, s := range r.Sources {
		icon := "✅"
		switch s.State {
		case SourceOutage:
			icon = "⚠️"
		case SourceChanged:
			icon = "❌"
		}
		fmt.Fprintf(&b, "| %s | %s %s | %d | %s |\n", s.Name, icon, s.State, s.Items, sanitize(s.Note, 160))
	}
	b.WriteString("\n_Unavailable_ is a temporary outage (retried tomorrow, no issue). _Format changed_ means the monitor no longer understands the source and opens an issue.\n\n")

	v := r.Versions
	fmt.Fprintf(&b, "### Official macOS client\n\nStudied: `%s` · latest release: `%s` · latest beta: `%s`\n\n", orDash(v.Baseline), orDash(v.LatestGA), orDash(v.LatestBeta))

	b.WriteString("### Findings that need investigation\n\n")
	var need, info []*Finding
	for _, f := range r.Findings {
		if f.NeedsIssue() {
			need = append(need, f)
		} else {
			info = append(info, f)
		}
	}
	if len(need) == 0 {
		b.WriteString("None.\n\n")
	} else {
		acts := map[*Finding]Action{}
		for _, a := range r.Actions {
			acts[a.Finding] = a
		}
		b.WriteString("| Severity | Impact | Finding | Issue |\n|---|---|---|---|\n")
		sortFindings(need)
		for _, f := range need {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", f.Severity, f.Impact, linked(f), actionText(acts[f], r.DryRun))
		}
		b.WriteString("\n")
	}
	if len(info) > 0 {
		sortFindings(info)
		fmt.Fprintf(&b, "<details><summary>%d informational or not applicable</summary>\n\n", len(info))
		for _, f := range info {
			fmt.Fprintf(&b, "- %s · %s · %s — %s\n", f.Severity, f.Impact, linked(f), sanitize(f.Reasoning, 200))
		}
		b.WriteString("\n</details>\n\n")
	}

	b.WriteString("### Go dependencies\n\n")
	if !r.VulnsChecked {
		b.WriteString("govulncheck: **not run** in this monitor run (see the workflow log).\n\n")
	} else if len(r.Vulns) == 0 {
		b.WriteString("govulncheck: no known vulnerabilities in the module graph.\n\n")
	} else {
		b.WriteString("| Vulnerability | Reachability | Module | Fixed in |\n|---|---|---|---|\n")
		for _, s := range r.Vulns {
			fmt.Fprintf(&b, "| [%s](https://pkg.go.dev/vuln/%s) | %s | `%s %s` | %s |\n", s.ID, url.PathEscape(s.ID), s.Level, s.Module, s.Version, orDash(s.Fixed))
		}
		b.WriteString("\n")
	}
	if len(r.Updates) > 0 {
		b.WriteString("Security-sensitive modules with a newer version (Dependabot opens the update PRs):\n\n")
		for _, u := range r.Updates {
			fmt.Fprintf(&b, "- `%s` %s → %s\n", u.Path, u.Version, u.Update)
		}
		b.WriteString("\n")
	}

	b.WriteString("### Offline compatibility tests\n\n")
	switch {
	case r.Tests == nil:
		fmt.Fprintf(&b, "Not run: %s\n\n", orDash(r.TestsErr))
	case r.Tests.ok():
		fmt.Fprintf(&b, "✅ %d passed, %d skipped.\n\n", r.Tests.Passed, r.Tests.Skipped)
	default:
		fmt.Fprintf(&b, "❌ %d passed, %d failed, %d skipped:\n\n", r.Tests.Passed, r.Tests.Failed, r.Tests.Skipped)
		for _, f := range r.Tests.Failures {
			fmt.Fprintf(&b, "- `%s`\n", f)
		}
		b.WriteString("\n")
	}

	b.WriteString("### Unresolved security findings\n\n")
	if len(r.OpenSec) == 0 {
		b.WriteString("None open.\n\n")
	} else {
		for _, is := range r.OpenSec {
			fmt.Fprintf(&b, "- [#%d](%s) %s\n", is.Number, is.HTMLURL, sanitize(is.Title, 160))
		}
		b.WriteString("\n")
	}
	if len(r.Problems) > 0 {
		b.WriteString("### Monitor problems\n\n")
		for _, p := range r.Problems {
			fmt.Fprintf(&b, "- %s\n", sanitize(p, 300))
		}
		b.WriteString("\n")
	}
	b.WriteString("### Recommended next actions\n\n")
	for _, a := range r.nextActions() {
		fmt.Fprintf(&b, "- %s\n", a)
	}
	return b.String()
}

func (r *Report) nextActions() []string {
	var out []string
	if c := r.critical(); len(c) > 0 {
		out = append(out, fmt.Sprintf("**%d critical finding(s)**: fix before the next release (see the issues above).", len(c)))
	}
	if r.Tests != nil && !r.Tests.ok() {
		out = append(out, "Offline compatibility tests failed on main: investigate before merging anything else.")
	} else if r.TestsExpected && r.Tests == nil {
		out = append(out, "The offline compatibility tests produced no readable output: check the workflow log.")
	}
	n := 0
	for _, a := range r.Actions {
		if a.Do == "create" || a.Do == "update" || a.Do == "comment" {
			n++
		}
	}
	if n > 0 {
		out = append(out, fmt.Sprintf("Triage the %d new or updated monitor issue(s).", n))
	}
	for _, a := range r.Actions {
		if a.Do == "deferred" {
			out = append(out, "Some findings were deferred (new-issue limit or rate limit); they are picked up by the next run.")
			break
		}
	}
	for _, s := range r.failedSources() {
		if s.State == SourceChanged {
			out = append(out, "Update the monitor for the changed source: "+s.Name+".")
		}
	}
	if len(r.failedSources()) == len(r.Sources) && len(r.Sources) > 0 {
		out = append(out, "Every upstream source failed: check the runner's network before trusting this report.")
	}
	if len(out) == 0 {
		out = append(out, "Nothing to do.")
	}
	return out
}

func linked(f *Finding) string {
	t := strings.ReplaceAll(sanitize(f.Title, 140), "|", "\\|")
	if u := safeURL(f.URL); u != "" {
		return "[" + strings.NewReplacer("[", "\\[", "]", "\\]").Replace(t) + "](" + u + ")"
	}
	return t
}

func actionText(a Action, dry bool) string {
	ref := ""
	if a.Issue != nil && a.Issue.Number > 0 {
		ref = fmt.Sprintf("#%d", a.Issue.Number)
	}
	prefix := ""
	if dry {
		prefix = "would "
	}
	switch a.Do {
	case "create":
		if dry {
			return "would open"
		}
		return "opened " + ref
	case "update":
		return prefix + "update " + ref
	case "comment":
		return prefix + "comment on closed " + ref
	case "unchanged":
		return ref + " (no new evidence)"
	case "tracked":
		if ref == "" {
			return "covered by another entry in this run"
		}
		return "already tracked in " + ref
	case "deferred":
		return "deferred " + a.Err
	case "error":
		return "error: " + sanitize(a.Err, 80)
	}
	return "—"
}

func sortFindings(fs []*Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity != fs[j].Severity {
			return fs[i].Severity > fs[j].Severity
		}
		return fs[i].Published.After(fs[j].Published)
	})
}
