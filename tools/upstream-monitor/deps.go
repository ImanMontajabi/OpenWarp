package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// ---- govulncheck -format json ----

type govulnOSV struct {
	ID         string   `json:"id"`
	Aliases    []string `json:"aliases"`
	Summary    string   `json:"summary"`
	Details    string   `json:"details"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

type govulnFrame struct {
	Module   string `json:"module"`
	Version  string `json:"version"`
	Package  string `json:"package"`
	Function string `json:"function"`
	Receiver string `json:"receiver"`
}

type govulnMsg struct {
	OSV     *govulnOSV `json:"osv"`
	Finding *struct {
		OSV          string        `json:"osv"`
		FixedVersion string        `json:"fixed_version"`
		Trace        []govulnFrame `json:"trace"`
	} `json:"finding"`
	Config *struct {
		DB string `json:"db"`
	} `json:"config"`
}

// Reachability levels reported by govulncheck.
const (
	levelSymbol  = "symbol"  // OpenWarp calls the vulnerable function
	levelPackage = "package" // OpenWarp imports the vulnerable package, the function is not called
	levelModule  = "module"  // only the module is required
)

type vulnSummary struct {
	ID, Level, Module, Version, Fixed, Package, Function string
}

// analyzeGovulncheck turns govulncheck's JSON stream into findings. Called code is a confirmed, reachable
// vulnerability (Critical); imported-but-not-called is Medium; module-only is Low.
func analyzeGovulncheck(data []byte) ([]*Finding, []vulnSummary, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	osvs := map[string]*govulnOSV{}
	best := map[string]vulnSummary{}
	sawConfig := false
	rank := map[string]int{levelModule: 0, levelPackage: 1, levelSymbol: 2}
	for {
		var m govulnMsg
		err := dec.Decode(&m)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("govulncheck output is not its JSON stream: %w", err)
		}
		if m.Config != nil {
			sawConfig = true
		}
		if m.OSV != nil && m.OSV.ID != "" {
			osvs[m.OSV.ID] = m.OSV
		}
		if f := m.Finding; f != nil && f.OSV != "" && len(f.Trace) > 0 {
			top := f.Trace[0]
			lvl := levelModule
			switch {
			case top.Function != "":
				lvl = levelSymbol
			case top.Package != "":
				lvl = levelPackage
			}
			s := vulnSummary{ID: f.OSV, Level: lvl, Module: top.Module, Version: top.Version, Fixed: f.FixedVersion, Package: top.Package}
			if top.Function != "" {
				s.Function = strings.TrimPrefix(top.Receiver+"."+top.Function, ".")
			}
			if old, ok := best[f.OSV]; !ok || rank[lvl] > rank[old.Level] {
				best[f.OSV] = s
			}
		}
	}
	if !sawConfig {
		return nil, nil, errors.New("govulncheck output has no config message (did it run?)")
	}
	ids := make([]string, 0, len(best))
	for id := range best {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var out []*Finding
	var sums []vulnSummary
	for _, id := range ids {
		s := best[id]
		sums = append(sums, s)
		o := osvs[id]
		f := &Finding{
			ID:         "govuln:" + id,
			Kind:       KindDependency,
			Source:     "govulncheck",
			URL:        "https://pkg.go.dev/vuln/" + id,
			Confidence: "high",
			Components: componentsForModule(s.Module),
		}
		title := id
		if o != nil {
			for _, a := range o.Aliases {
				f.Keys = append(f.Keys, "cve:"+a)
			}
			if o.Summary != "" {
				title += ": " + cleanTitle(o.Summary)
			}
		}
		f.Title = "Go vulnerability " + title + " in " + s.Module
		f.Evidence = []string{
			fmt.Sprintf("Module %s %s; fixed in %s", s.Module, s.Version, orDash(s.Fixed)),
			"Reachability (govulncheck): " + s.Level,
		}
		if s.Function != "" {
			f.Evidence = append(f.Evidence, "Called: "+s.Package+"."+s.Function)
		}
		if o != nil && len(o.Aliases) > 0 {
			f.Evidence = append(f.Evidence, "Aliases: "+strings.Join(o.Aliases, ", "))
		}
		switch s.Level {
		case levelSymbol:
			f.Severity, f.Impact = SevCritical, ImpactConfirmed
			f.Reasoning = "govulncheck found a call path from OpenWarp to the vulnerable function."
		case levelPackage:
			f.Severity, f.Impact = SevMedium, ImpactPotential
			f.Reasoning = "OpenWarp imports the vulnerable package but govulncheck found no call to the vulnerable function."
		default:
			f.Severity, f.Impact = SevLow, ImpactNotApplicable
			f.Reasoning = "Only the module is required; the vulnerable package is not imported."
		}
		if s.Fixed != "" {
			f.Remediation = fmt.Sprintf("Upgrade %s to %s or later (`go get %s@%s && go mod tidy`) in a pull request; "+
				"Dependabot security updates may already have opened one. Merge only after CI passes.", s.Module, s.Fixed, s.Module, s.Fixed)
		} else {
			f.Remediation = "No fixed version is published yet. Check the advisory for workarounds."
		}
		f.Investigate = []string{"Read the advisory and confirm the call path govulncheck reports.", "Run `GOOS=darwin govulncheck -show traces ./...` locally."}
		out = append(out, f)
	}
	return out, sums, nil
}

func componentsForModule(mod string) []Component {
	switch {
	case strings.Contains(mod, "quic-go"):
		return componentsNamed("MASQUE tunnel")
	case strings.Contains(mod, "wireguard"), strings.Contains(mod, "gvisor"):
		return componentsNamed("WireGuard tunnel", "Local proxy")
	case strings.HasPrefix(mod, "golang.org/x/crypto"), mod == "stdlib":
		return componentsNamed("MASQUE tunnel", "Registration, keys and API client")
	}
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// ---- go list -m -u -json all ----

// securitySensitive are the modules whose updates the summary always lists: networking, crypto, VPN.
var securitySensitive = []string{
	"github.com/quic-go/quic-go", "github.com/quic-go/qpack", "golang.zx2c4.com/wireguard",
	"golang.org/x/crypto", "golang.org/x/net", "golang.org/x/sys", "gvisor.dev/gvisor",
}

type moduleUpdate struct{ Path, Version, Update string }

func analyzeGoList(data []byte) ([]moduleUpdate, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	var out []moduleUpdate
	n := 0
	for {
		var m struct {
			Path    string
			Version string
			Main    bool
			Update  *struct{ Version string }
		}
		err := dec.Decode(&m)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("go list output: %w", err)
		}
		n++
		if m.Main || m.Update == nil {
			continue
		}
		for _, p := range securitySensitive {
			if m.Path == p {
				out = append(out, moduleUpdate{m.Path, m.Version, m.Update.Version})
			}
		}
	}
	if n == 0 {
		return nil, errors.New("go list output is empty")
	}
	return out, nil
}

// ---- go test -json ----

type testRun struct {
	Passed, Failed, Skipped int
	Failures                []string
}

func analyzeGoTest(data []byte) (testRun, error) {
	var r testRun
	dec := json.NewDecoder(bytes.NewReader(data))
	n := 0
	failedIn := map[string]bool{}
	for {
		var e struct{ Action, Package, Test string }
		err := dec.Decode(&e)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return r, fmt.Errorf("go test -json output: %w", err)
		}
		n++
		switch e.Action {
		case "pass":
			if e.Test != "" {
				r.Passed++
			}
		case "skip":
			if e.Test != "" {
				r.Skipped++
			}
		case "fail":
			if e.Test != "" {
				r.Failed++
				r.Failures = append(r.Failures, e.Package+" "+e.Test)
				failedIn[e.Package] = true
			} else if e.Package != "" && !failedIn[e.Package] {
				// A package that fails without a failing test (build error, panic in init).
				r.Failures = append(r.Failures, e.Package+" (package)")
			}
		}
	}
	if n == 0 {
		return r, errors.New("go test -json output is empty")
	}
	return r, nil
}

func (r testRun) ok() bool { return len(r.Failures) == 0 && r.Passed > 0 }
