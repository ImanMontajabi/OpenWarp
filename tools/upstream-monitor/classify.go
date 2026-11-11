package main

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Severity of a finding. Assigned from evidence, never from the upstream's own wording alone: a fixed bug in
// the official client is not a bug in OpenWarp.
type Severity int

const (
	SevLow Severity = iota
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	return [...]string{"Low", "Medium", "High", "Critical"}[s]
}

// Impact on OpenWarp, separate from severity.
type Impact string

const (
	ImpactConfirmed     Impact = "Confirmed affected"
	ImpactPotential     Impact = "Potentially affected"
	ImpactNotApplicable Impact = "Not applicable"
	ImpactInsufficient  Impact = "Insufficient evidence"
)

// Kind decides the issue labels.
type Kind string

const (
	KindSecurity      Kind = "security"
	KindCompatibility Kind = "compatibility"
	KindDependency    Kind = "dependency"
	KindMonitor       Kind = "monitor" // a monitored source changed format
)

// Component is an OpenWarp subsystem that an upstream change can touch, with the code and tests to look at.
type Component struct {
	Name  string
	Code  []string
	Tests []string
}

type componentRule struct {
	Component
	re *regexp.Regexp
	// protocol components are shared by every official platform (same edge, same API), so a change on
	// Windows or Linux is still worth noting; the others only matter for macOS entries.
	protocol bool
}

var componentRules = []componentRule{
	{Component{"MASQUE tunnel", []string{"internal/tunnel/masque.go"},
		[]string{"TestMasqueConnectIP", "TestMasqueRejectsWrongEdgeKey", "TestMasqueCompat*"}},
		regexp.MustCompile(`(?i)\bmasque\b|http/3|\bquic\b|connect-ip|\bh3\b`), true},
	{Component{"WireGuard tunnel", []string{"internal/tunnel/wireguard.go"},
		[]string{"TestWireGuardWithReservedBytes"}},
		regexp.MustCompile(`(?i)wireguard`), true},
	{Component{"Registration, keys and API client", []string{"internal/api/api.go", "internal/daemon/engine.go (Register, ensureKey)"},
		[]string{"TestRegister*", "TestAPICompat*", "TestKeyEnrollmentWithoutPeersIsAnErrorNotACrash", "TestEndToEndProxyModeOverMasque"}},
		regexp.MustCompile(`(?i)registration|\blicen[cs]e\b|warp\+|api authentication|key rotation|\btoken\b|device list`), true},
	{Component{"Protocol selection and reconnect", []string{"internal/daemon/engine.go (loop, endpointCandidates)"},
		[]string{"TestEndpointCandidatesCompat", "TestEndToEndProxyModeOverMasque"}},
		regexp.MustCompile(`(?i)tunnel protocol|protocol order|fallback|reconnect|connectivity[- ]check|tunnel (and api )?endpoints?|endpoint (override|port)|custom endpoint`), true},
	{Component{"Post-quantum key agreement", []string{"internal/tunnel/masque.go (tlsConfig)"},
		[]string{"TestMasqueConnectIP"}},
		regexp.MustCompile(`(?i)post-quantum|\bpqc?\b|ml-kem|kyber`), true},
	{Component{"DNS", []string{"internal/dnsproxy", "internal/sysnet/sysnet_darwin.go"},
		[]string{"TestFallbackDomainsUseLocalResolver", "TestFamilies"}},
		regexp.MustCompile(`(?i)\bdns\b|\bdoh\b|\bdot\b|resolver|local domain fallback`), false},
	{Component{"Local proxy", []string{"internal/proxy"},
		[]string{"TestEndToEndProxyModeOverMasque"}},
		regexp.MustCompile(`(?i)proxy mode|local proxy|socks|http proxy`), false},
	{Component{"Routing and split tunnel", []string{"internal/sysnet/sysnet_darwin.go"},
		nil},
		regexp.MustCompile(`(?i)split tunnel|\broutes?\b|routing|exclude list|include list`), false},
	{Component{"Privileged service and installer", []string{"cmd/openwarp/service.go", "ui/macos/Setup.swift (AdminInstaller)"},
		[]string{"TestLaunchdPlistRunsTheRootOwnedHelper", "TestRootOnlyRejectsFilesOtherUsersCanReplace"}},
		regexp.MustCompile(`(?i)installer|privilege|service path|launchd|launch ?daemon|\broot\b|helper`), false},
}

var (
	// Features of the official client that OpenWarp does not implement (Zero Trust, MDM, diagnostics...).
	notImplementedRE = regexp.MustCompile(`(?i)zero trust|\bmdm\b|managed (network|registration|device|deployment)|` +
		`organi[sz]ation|gateway polic|secure web gateway|device posture|lock warp|override code|support_uri|\btpm\b|` +
		`\bteams\b|warp-diag|access app|device profile|\bdex\b|reauthenticat|captive portal|default profile|` +
		`home screen|tray|notification|switch organi[sz]ations|global acceleration|service token|allowed to override|` +
		`\bsaml\b|identity provider|\bidp\b|virtual network|managed network|posture|\bdlp\b|browser isolation|digital experience`)
	// "Gateway" as a product name (case-sensitive), not the network's default gateway.
	gatewayProductRE = regexp.MustCompile(`\bGateway\b`)
	securityRE       = regexp.MustCompile(`(?i)security (issue|fix|vulnerab|update)|vulnerab|\bcve-\d{4}-\d+|exploit|privilege escalation|` +
		`arbitrary (code|file)|bypass|plaintext|man-in-the-middle|denial of service`)
	platformRE = regexp.MustCompile(`(?i)\b(macos|mac os|windows|linux|android|ios|mobile|chromeos)\b`)
)

// SentenceClass is the analysis of one upstream sentence.
type SentenceClass struct {
	Text       string
	Key        string // stable id of the normalised sentence
	Components []Component
	Security   bool
	NotImpl    bool
}

func classifySentence(s string) SentenceClass {
	c := SentenceClass{Text: s, Key: "sentence:" + shortHash(normalize(s))}
	c.Security = securityRE.MatchString(s)
	c.NotImpl = notImplementedRE.MatchString(s) || gatewayProductRE.MatchString(s)
	for _, r := range componentRules {
		if r.re.MatchString(s) {
			c.Components = append(c.Components, r.Component)
		}
	}
	return c
}

// relevant reports whether a sentence is worth an investigation for an entry on platform (lower case,
// "" when the entry names none).
func (c SentenceClass) relevant(platform string) bool {
	if c.NotImpl || len(c.Components) == 0 {
		return false
	}
	if platform == "" || platform == "macos" {
		return true
	}
	for _, comp := range c.Components {
		for _, r := range componentRules {
			if r.Name == comp.Name && r.protocol {
				return true
			}
		}
	}
	return false
}

// Finding is one thing the maintainer may need to look at.
type Finding struct {
	ID         string   // stable de-duplication key (advisory id, CVE, canonical URL + version...)
	Keys       []string // further keys that identify the same finding (aliases, sentence ids)
	Kind       Kind
	Title      string
	Source     string // source id
	URL        string
	Published  time.Time
	Severity   Severity
	Impact     Impact
	Confidence string // high, medium, low
	Components []Component
	Evidence   []string // sanitised upstream text and facts
	// EvidenceKeys, when set, has one key per Evidence line (changelog sentences), so lines that another
	// issue already tracks can be dropped.
	EvidenceKeys []string
	Reasoning    string
	Investigate  []string
	Remediation  string
}

// NeedsIssue: only findings that need an investigation get an issue; the rest are in the run summary.
func (f *Finding) NeedsIssue() bool {
	return f.Severity >= SevMedium && f.Impact != ImpactNotApplicable
}

// EvidenceHash changes when the evidence changes, which is what makes an existing issue worth updating.
func (f *Finding) EvidenceHash() string {
	return shortHash(f.Severity.String() + "\x00" + string(f.Impact) + "\x00" + strings.Join(f.Evidence, "\x00"))
}

func (f *Finding) Tests() []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range f.Components {
		for _, t := range c.Tests {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	return out
}

func mergeComponents(cs ...[]Component) []Component {
	seen := map[string]bool{}
	var out []Component
	for _, list := range cs {
		for _, c := range list {
			if !seen[c.Name] {
				seen[c.Name] = true
				out = append(out, c)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func shortHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}

var spaceRE = regexp.MustCompile(`\s+`)

func normalize(s string) string {
	return strings.ToLower(strings.TrimSpace(spaceRE.ReplaceAllString(s, " ")))
}

// platformsIn lists the platforms a text names, lower case and de-duplicated.
func platformsIn(s string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range platformRE.FindAllString(s, -1) {
		p := strings.ToLower(m)
		if p == "mac os" {
			p = "macos"
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// assessAdvisory classifies a Cloudflare security advisory or CVE about the official client. It never
// concludes "Confirmed affected": that needs a reproduction in OpenWarp, which a monitor cannot do.
func assessAdvisory(text string) (Impact, Severity, []Component, string) {
	plats := platformsIn(text)
	onlyOther := len(plats) > 0
	for _, p := range plats {
		if p == "macos" {
			onlyOther = false
		}
	}
	sc := classifySentence(text)
	switch {
	case sc.NotImpl:
		return ImpactNotApplicable, SevLow, sc.Components,
			"The advisory concerns a feature of the official client that OpenWarp does not implement (Zero Trust, MDM, Lock WARP and similar)."
	case onlyOther:
		reason := "The advisory names only other platforms (" + strings.Join(plats, ", ") + "); OpenWarp runs on macOS only."
		if len(sc.Components) > 0 {
			reason += " OpenWarp has a comparable component (" + sc.Components[0].Name + "), worth a look when it is next changed."
		}
		return ImpactNotApplicable, SevLow, sc.Components, reason
	case len(sc.Components) > 0:
		return ImpactPotential, SevHigh, sc.Components,
			"The advisory applies to macOS or names no platform, and OpenWarp implements a comparable component. " +
				"The official client's bug is not automatically OpenWarp's: check the component listed below."
	default:
		return ImpactInsufficient, SevMedium, nil,
			"The advisory applies to macOS or names no platform, but no OpenWarp component could be matched from its text."
	}
}
