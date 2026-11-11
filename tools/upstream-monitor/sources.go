package main

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ---- RSS (Cloudflare changelog and blog) ----

type rssDoc struct {
	XMLName xml.Name `xml:"rss"`
	Channel struct {
		Title string    `xml:"title"`
		Items []rssItem `xml:"item"`
	} `xml:"channel"`
}

type rssItem struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	GUID        string `xml:"guid"`
	PubDate     string `xml:"pubDate"`
	Description string `xml:"description"`
}

func parseRSS(body []byte) ([]rssItem, error) {
	var doc rssDoc
	if err := xml.Unmarshal(body, &doc); err != nil {
		return nil, changed(0, fmt.Errorf("not an RSS document: %w", err))
	}
	if len(doc.Channel.Items) == 0 {
		return nil, changed(0, errors.New("the feed has no items"))
	}
	var bad int
	for _, it := range doc.Channel.Items {
		if it.Title == "" || it.Link == "" {
			bad++
		}
	}
	if bad == len(doc.Channel.Items) {
		return nil, changed(0, errors.New("no item has a title and link"))
	}
	return doc.Channel.Items, nil
}

func parseTime(s string) time.Time {
	for _, layout := range []string{time.RFC1123Z, time.RFC1123, time.RFC3339, "2006-01-02T15:04:05.000", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, strings.TrimSpace(s)); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

var (
	tagRE        = regexp.MustCompile(`(?s)<[^>]*>`)
	blockTagRE   = regexp.MustCompile(`(?i)</?(p|li|ul|ol|h[1-6]|br|div|tr)\b[^>]*>`)
	sentenceEnd  = regexp.MustCompile(`([.!?])\s+`)
	changelogRE  = regexp.MustCompile(`(?i)\bfor (macOS|Windows|Linux|iOS|Android|ChromeOS)\b.*\(version ([0-9]+(?:\.[0-9]+)+)\)`)
	betaSuffixRE = regexp.MustCompile(`(?i)-beta/?$|\bbeta\b`)
)

// htmlToText turns feed HTML into plain text lines (block elements become line breaks).
func htmlToText(s string) []string {
	s = blockTagRE.ReplaceAllString(s, "\n")
	s = tagRE.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	var lines []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(spaceRE.ReplaceAllString(l, " ")); l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

func splitSentences(lines []string) []string {
	var out []string
	for _, l := range lines {
		for _, s := range strings.Split(sentenceEnd.ReplaceAllString(l, "$1\n"), "\n") {
			if s = strings.TrimSpace(s); len(s) > 3 {
				out = append(out, s)
			}
		}
	}
	return out
}

// ---- versions ----

type version []int

func parseVersion(s string) version {
	var v version
	for _, p := range strings.Split(strings.TrimPrefix(strings.TrimSpace(s), "m-"), ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		v = append(v, n)
	}
	return v
}

func (a version) less(b version) bool {
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			return x < y
		}
	}
	return false
}

// Versions tracks the official macOS client against the version OpenWarp was studied from.
type Versions struct {
	Baseline      string
	LatestGA      string
	LatestGAURL   string
	LatestBeta    string
	LatestBetaURL string
}

func (v *Versions) observe(ver, link string, beta bool) {
	cur := &v.LatestGA
	curURL := &v.LatestGAURL
	if beta {
		cur, curURL = &v.LatestBeta, &v.LatestBetaURL
	}
	if *cur == "" || parseVersion(*cur).less(parseVersion(ver)) {
		*cur, *curURL = ver, link
	}
}

// ---- Cloudflare One Client changelog ----

// analyzeChangelog reads the official client changelog: versions for every macOS entry, and for entries
// inside the lookback window the sentences that touch something OpenWarp implements.
func analyzeChangelog(body []byte, now time.Time, lookback time.Duration, baseline string) ([]*Finding, Versions, int, error) {
	items, err := parseRSS(body)
	if err != nil {
		return nil, Versions{}, 0, err
	}
	vers := Versions{Baseline: baseline}
	var out []*Finding
	parsed := 0
	for _, it := range items {
		link := canonicalURL(firstNonEmpty(it.Link, it.GUID))
		platform, ver := "", ""
		if m := changelogRE.FindStringSubmatch(it.Title); m != nil {
			platform, ver = strings.ToLower(m[1]), m[2]
			parsed++
		}
		beta := betaSuffixRE.MatchString(link) || betaSuffixRE.MatchString(it.Title)
		if platform == "macos" && ver != "" {
			vers.observe(ver, link, beta)
		}
		pub := parseTime(it.PubDate)
		if pub.IsZero() || now.Sub(pub) > lookback {
			continue
		}
		var hits []SentenceClass
		for _, s := range splitSentences(htmlToText(it.Description)) {
			if c := classifySentence(s); c.relevant(platform) {
				hits = append(hits, c)
			}
		}
		if len(hits) == 0 {
			continue
		}
		f := &Finding{
			ID:         "cf-changelog:" + link,
			Kind:       KindCompatibility,
			Title:      "Official client change to check: " + strings.TrimPrefix(cleanTitle(it.Title), "Cloudflare One Client - "),
			Source:     "cf-changelog",
			URL:        link,
			Published:  pub,
			Severity:   SevMedium,
			Impact:     ImpactInsufficient,
			Confidence: "low",
		}
		security := false
		for _, h := range hits {
			f.Keys = append(f.Keys, h.Key)
			f.EvidenceKeys = append(f.EvidenceKeys, h.Key)
			f.Components = mergeComponents(f.Components, h.Components)
			f.Evidence = append(f.Evidence, h.Text)
			security = security || h.Security
		}
		if security {
			f.Kind, f.Severity, f.Impact = KindSecurity, SevHigh, ImpactPotential
		}
		if platform != "" && platform != "macos" {
			// Usually repeated in the macOS entry; kept in the summary only.
			f.Severity = SevLow
		}
		f.Reasoning = "The official client changed behaviour in an area OpenWarp also implements. Its code is closed, " +
			"so whether OpenWarp shares the old behaviour is unknown until the components below are checked."
		f.Investigate = []string{
			"Read the release note and decide whether the described behaviour exists in OpenWarp.",
			"Check the listed code paths and run the listed tests.",
			"If OpenWarp is affected, add a regression test and fix it in a separate, reviewed pull request.",
		}
		out = append(out, f)
	}
	if parsed == 0 {
		return nil, vers, len(items), changed(0, errors.New("no entry title has the expected 'for <platform> (version x.y.z)' form"))
	}
	if b := parseVersion(baseline); b != nil && vers.LatestGA != "" && b.less(parseVersion(vers.LatestGA)) {
		out = append(out, &Finding{
			ID:         "cf-macos-ga-newer-than:" + baseline,
			Kind:       KindCompatibility,
			Title:      "Official macOS client " + vers.LatestGA + " is newer than the version OpenWarp was studied from (" + baseline + ")",
			Source:     "cf-changelog",
			URL:        vers.LatestGAURL,
			Severity:   SevMedium,
			Impact:     ImpactInsufficient,
			Confidence: "medium",
			Components: mergeComponents(componentsNamed("Registration, keys and API client", "MASQUE tunnel", "WireGuard tunnel")),
			Evidence: []string{
				"Studied version (api.MacClientVersion): " + baseline,
				"Latest macOS release (GA) in the changelog: " + vers.LatestGA,
			},
			Reasoning: "OpenWarp mirrors protocol details of one official release. A newer release can change the API " +
				"version path, client version header, SNI, ports or MASQUE settings; nothing is known to have changed yet.",
			Investigate: []string{
				"Compare the protocol facts in CLAUDE.md with the new release (strings of the daemon binary, release notes).",
				"Run the live compatibility workflow (Actions → Live compatibility) if a test registration is configured.",
				"Update api.MacClientVersion only after the new values are verified.",
			},
		})
	}
	return out, vers, len(items), nil
}

func componentsNamed(names ...string) []Component {
	var out []Component
	for _, n := range names {
		for _, r := range componentRules {
			if r.Name == n {
				out = append(out, r.Component)
			}
		}
	}
	return out
}

// ---- Cloudflare blog (WARP tag) ----

func analyzeBlog(body []byte, now time.Time, lookback time.Duration) ([]*Finding, int, error) {
	items, err := parseRSS(body)
	if err != nil {
		return nil, 0, err
	}
	var out []*Finding
	for _, it := range items {
		pub := parseTime(it.PubDate)
		if pub.IsZero() || now.Sub(pub) > lookback {
			continue
		}
		text := cleanTitle(it.Title) + ". " + strings.Join(htmlToText(it.Description), " ")
		sc := classifySentence(text)
		var protocol []Component
		for _, c := range sc.Components {
			for _, r := range componentRules {
				if r.Name == c.Name && r.protocol {
					protocol = append(protocol, c)
				}
			}
		}
		f := &Finding{
			ID:         "cf-blog:" + canonicalURL(it.Link),
			Kind:       KindCompatibility,
			Title:      "Cloudflare blog: " + cleanTitle(it.Title),
			Source:     "cf-blog",
			URL:        canonicalURL(it.Link),
			Published:  pub,
			Severity:   SevLow,
			Impact:     ImpactNotApplicable,
			Confidence: "low",
			Components: protocol,
			Evidence:   []string{truncate(text, 400)},
			Reasoning:  "A WARP announcement without a protocol-level topic OpenWarp implements.",
		}
		if len(protocol) > 0 && !sc.NotImpl {
			f.Severity, f.Impact = SevMedium, ImpactInsufficient
			f.Reasoning = "A WARP announcement that mentions protocol behaviour OpenWarp implements (" + protocol[0].Name + ")."
			f.Investigate = []string{"Read the post and check whether the announced change reaches the consumer WARP service OpenWarp uses."}
		}
		out = append(out, f)
	}
	return out, len(items), nil
}

// ---- Cloudflare security advisories (GitHub repository advisories of cloudflare/advisories) ----

type ghAdvisory struct {
	GHSA        string  `json:"ghsa_id"`
	CVE         *string `json:"cve_id"`
	URL         string  `json:"html_url"`
	Summary     string  `json:"summary"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	Published   string  `json:"published_at"`
	Updated     string  `json:"updated_at"`
	Withdrawn   *string `json:"withdrawn_at"`
}

var warpRE = regexp.MustCompile(`(?i)\bwarp\b|1\.1\.1\.1`)

func analyzeAdvisories(body []byte) ([]*Finding, int, error) {
	var advs []ghAdvisory
	if err := json.Unmarshal(body, &advs); err != nil {
		return nil, 0, changed(0, fmt.Errorf("advisories: %w", err))
	}
	var out []*Finding
	for _, a := range advs {
		if a.GHSA == "" {
			return nil, len(advs), changed(0, errors.New("advisory without ghsa_id"))
		}
		text := a.Summary + ". " + a.Description
		if a.Withdrawn != nil || !warpRE.MatchString(text) {
			continue
		}
		impact, sev, comps, reason := assessAdvisory(text)
		f := &Finding{
			ID:         "ghsa:" + a.GHSA,
			Kind:       KindSecurity,
			Title:      "Cloudflare advisory " + a.GHSA + ": " + cleanTitle(a.Summary),
			Source:     "cf-advisories",
			URL:        a.URL,
			Published:  parseTime(a.Published),
			Severity:   sev,
			Impact:     impact,
			Confidence: "medium",
			Components: comps,
			Evidence:   []string{cleanTitle(a.Summary), "Cloudflare's severity for its own client: " + a.Severity},
			Reasoning:  reason,
		}
		if a.CVE != nil && *a.CVE != "" {
			f.Keys = append(f.Keys, "cve:"+*a.CVE)
			f.Evidence = append(f.Evidence, "CVE: "+*a.CVE)
		}
		if impact != ImpactNotApplicable {
			f.Investigate = []string{
				"Identify the affected subsystem from the advisory.",
				"Check whether OpenWarp implements comparable behaviour in the components listed.",
				"If it plausibly applies, write a test that demonstrates it before changing code.",
			}
		}
		out = append(out, f)
	}
	return out, len(advs), nil
}

// ---- NVD CVE API (keyword "Cloudflare WARP") ----

type nvdDoc struct {
	TotalResults    *int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			Status       string `json:"vulnStatus"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

var ghsaRE = regexp.MustCompile(`GHSA(-[23456789cfghjmpqrvwx]{4}){3}`)

func analyzeNVD(body []byte) ([]*Finding, int, error) {
	var doc nvdDoc
	if err := json.Unmarshal(body, &doc); err != nil || doc.TotalResults == nil {
		return nil, 0, changed(0, fmt.Errorf("not an NVD CVE API 2.0 response: %v", err))
	}
	var out []*Finding
	for _, v := range doc.Vulnerabilities {
		c := v.CVE
		if c.ID == "" || strings.EqualFold(c.Status, "Rejected") {
			continue
		}
		var desc string
		for _, d := range c.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
			}
		}
		if !warpRE.MatchString(desc) {
			continue
		}
		impact, sev, comps, reason := assessAdvisory(desc)
		f := &Finding{
			ID:         "cve:" + c.ID,
			Kind:       KindSecurity,
			Title:      c.ID + ": " + truncate(cleanTitle(desc), 90),
			Source:     "nvd",
			URL:        "https://nvd.nist.gov/vuln/detail/" + url.PathEscape(c.ID),
			Published:  parseTime(c.Published),
			Severity:   sev,
			Impact:     impact,
			Confidence: "medium",
			Components: comps,
			Evidence:   []string{truncate(desc, 600), "NVD status: " + c.Status},
			Reasoning:  reason,
		}
		for _, r := range c.References {
			if g := ghsaRE.FindString(r.URL); g != "" {
				f.Keys = append(f.Keys, "ghsa:"+g)
			}
		}
		if impact != ImpactNotApplicable {
			f.Investigate = []string{
				"Check whether OpenWarp implements comparable behaviour in the components listed.",
				"If it plausibly applies, write a test that demonstrates it before changing code.",
			}
		}
		out = append(out, f)
	}
	return out, len(doc.Vulnerabilities), nil
}

// ---- helpers ----

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// canonicalURL drops query, fragment and trailing slash differences so the same page has one id.
func canonicalURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return strings.TrimSpace(raw)
	}
	u.RawQuery, u.Fragment = "", ""
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String()
}

func cleanTitle(s string) string {
	return strings.TrimSpace(spaceRE.ReplaceAllString(html.UnescapeString(tagRE.ReplaceAllString(s, " ")), " "))
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// mergeFindings folds findings that share an id or key (a GHSA and its CVE from NVD) into the first one.
func mergeFindings(in []*Finding) []*Finding {
	var out []*Finding
	byKey := map[string]*Finding{}
	for _, f := range in {
		// Changelog sentence keys are not identities: platforms share sentences but are separate entries.
		keys := []string{f.ID}
		for _, k := range f.Keys {
			if !strings.HasPrefix(k, "sentence:") {
				keys = append(keys, k)
			}
		}
		var into *Finding
		for _, k := range keys {
			if g, ok := byKey[k]; ok {
				into = g
				break
			}
		}
		if into == nil {
			out = append(out, f)
			for _, k := range keys {
				byKey[k] = f
			}
			continue
		}
		for _, k := range keys {
			if _, ok := byKey[k]; !ok {
				byKey[k] = into
				if k != into.ID {
					into.Keys = append(into.Keys, k)
				}
			}
		}
		if f.URL != "" && f.URL != into.URL {
			into.Evidence = append(into.Evidence, "Also reported at "+f.URL)
		}
		if f.Severity > into.Severity && f.Impact != ImpactNotApplicable {
			into.Severity, into.Impact = f.Severity, f.Impact
		}
		into.Components = mergeComponents(into.Components, f.Components)
	}
	return out
}
