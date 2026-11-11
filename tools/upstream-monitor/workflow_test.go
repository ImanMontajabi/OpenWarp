package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func workflow(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// jobPermissions returns the permission lines of the first job-level permissions block.
func jobPermissions(wf string) []string {
	var out []string
	in := false
	for _, l := range strings.Split(wf, "\n") {
		switch {
		case l == "    permissions:":
			in = true
		case in && strings.HasPrefix(l, "      ") && strings.TrimSpace(l) != "":
			out = append(out, strings.TrimSpace(strings.SplitN(l, "#", 2)[0]))
		case in:
			return out
		}
	}
	return out
}

var (
	usesRE     = regexp.MustCompile(`(?m)^\s*-?\s*uses:\s*(\S+)`)
	pinnedRE   = regexp.MustCompile(`@[0-9a-f]{40}$`)
	untrusted  = regexp.MustCompile(`\$\{\{\s*github\.(event|head_ref)`)
	forbidden  = regexp.MustCompile(`(?i)git push|gh release|gh pr merge|gh api -X (POST|PATCH|PUT|DELETE)|contents: write|pull_request_target|sudo |networksetup|route (add|delete)`)
	topReadRE  = regexp.MustCompile(`(?m)^permissions:\n  contents: read\n`)
	triggersRE = regexp.MustCompile(`(?ms)^on:\n(.*?)\n\S`)
)

// The monitoring workflows stay read-mostly, pinned and inert towards upstream content.
func TestWorkflowSafety(t *testing.T) {
	for _, name := range []string{"upstream-monitor.yml", "live-compat.yml"} {
		wf := workflow(t, name)
		if !topReadRE.MatchString(wf) {
			t.Errorf("%s: top-level permissions must be contents: read only", name)
		}
		for _, m := range usesRE.FindAllStringSubmatch(wf, -1) {
			if !pinnedRE.MatchString(m[1]) {
				t.Errorf("%s: action %s is not pinned to a commit SHA", name, m[1])
			}
		}
		if m := untrusted.FindString(wf); m != "" {
			t.Errorf("%s: interpolates untrusted event data (%s)", name, m)
		}
		if m := forbidden.FindString(wf); m != "" {
			t.Errorf("%s: contains %q", name, m)
		}
		trig := triggersRE.FindStringSubmatch(wf)
		if trig == nil || strings.Contains(trig[1], "pull_request") || strings.Contains(trig[1], "push") {
			t.Errorf("%s: must not run on pushes or pull requests (an upstream outage must not block development)", name)
		}
	}

	mon := workflow(t, "upstream-monitor.yml")
	if !strings.Contains(mon, "schedule:") || !strings.Contains(mon, "workflow_dispatch:") {
		t.Error("upstream-monitor.yml: needs a daily schedule and manual runs")
	}
	got := strings.Join(jobPermissions(mon), ",")
	if got != "contents: read,issues: write,actions: read" {
		t.Errorf("upstream-monitor.yml job permissions = %q", got)
	}

	live := workflow(t, "live-compat.yml")
	if strings.Contains(live, "schedule:") {
		t.Error("live-compat.yml must never run on a schedule")
	}
	if !strings.Contains(live, "environment: live-tests") {
		t.Error("live-compat.yml must run in the approval-gated live-tests environment")
	}
	if p := jobPermissions(live); len(p) != 0 {
		t.Errorf("live-compat.yml must not widen permissions: %v", p)
	}
	for _, leak := range []string{"cat \"$dir/state.json\"", "daemon.log\n", "set -x", "echo \"$LIVE_STATE"} {
		if strings.Contains(live, leak) {
			t.Errorf("live-compat.yml may print the test state or logs (%q)", leak)
		}
	}
}

// The monitor never runs commands: upstream content cannot reach a shell.
func TestMonitorRunsNoCommands(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		for _, bad := range []string{`"os/exec"`, `"syscall"`, `"plugin"`, `"unsafe"`} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s imports %s", f, bad)
			}
		}
	}
}
