# Maintenance monitoring

OpenWarp reproduces a closed-source client against a service it does not control. Cloudflare can change the
official client, the API or the edge at any time, and security fixes for the official client may or may not
matter for OpenWarp. This document describes how the repository watches for that. Everything here runs in
GitHub Actions; nothing is added to the app or the daemon, and no user data is involved.

## What runs, and when

| What | Where | When | Writes |
|---|---|---|---|
| Upstream monitor | `.github/workflows/upstream-monitor.yml` → `tools/upstream-monitor` | daily 06:17 UTC, and on demand | issues labelled `upstream-monitoring`; the job summary |
| Offline compatibility tests | every `go test ./...` (CI on every PR) and the monitor's daily run | every PR, daily | nothing |
| govulncheck (symbol level, darwin) | `security.yml` (required PR check) and the daily monitor | every PR, daily | monitor issues for reachable or imported vulnerabilities |
| Dependabot | `.github/dependabot.yml`, repository settings | weekly version PRs; security PRs as soon as an advisory is published | pull requests (never merged automatically) |
| Dependabot alerts, secret scanning with push protection | repository settings | continuously | GitHub's own alerts |
| Live compatibility | `.github/workflows/live-compat.yml` | **manual only**, after approval | the job summary |

The monitor is not a pull request check, so an upstream outage cannot block development. Its job fails, and
GitHub emails the maintainer, only when something must be acted on now:

- govulncheck reports a vulnerability whose code OpenWarp actually calls (Critical);
- the offline compatibility tests fail, or produce no output;
- no upstream source could be reached at all.

## Sources

All sources were checked by hand on 2026-11-10. The monitor uses machine-readable endpoints only; it does
not scrape HTML, log in, or download anything from Cloudflare except these documents.

| Source | Endpoint | Used for | Limits |
|---|---|---|---|
| Cloudflare One Client changelog | `https://developers.cloudflare.com/changelog/rss/cloudflare-one-client.xml` (RSS) | release notes per platform and version; the latest macOS release and beta | Notes describe the official client, mostly Zero Trust features; wording, not code. |
| Cloudflare security advisories | `GET https://api.github.com/repos/cloudflare/advisories/security-advisories` (GitHub REST) | advisories for the official clients (GHSA, CVE) | Only what Cloudflare publishes there. |
| NVD | `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Cloudflare%20WARP` with a modification window | CVEs not mirrored as GitHub advisories | Keyword search; NVD analysis can lag. One request per day (well under the unauthenticated limit). |
| Cloudflare blog | `https://blog.cloudflare.com/tag/warp/rss/` (RSS) | announcements (protocol changes, deprecations) | Marketing text; flagged only for protocol topics. |
| Go vulnerability database | `govulncheck -format json` | vulnerable dependencies, with reachability | Go modules and the standard library only. |
| Module proxy | `go list -m -u -json all` | newer versions of networking/crypto/VPN modules | Listed in the summary; Dependabot opens the PRs. |

Not used: the official app's update feed (undocumented), the official binaries, any Cloudflare account API.
Protocol facts (API paths, client version string, SNI, ports) still have to be re-checked by hand against a
new official release; the monitor only says when that is due.

## How findings are classified

Each finding has a **severity** and, separately, an **impact on OpenWarp**:

| Severity | Meaning here |
|---|---|
| Critical | Confirmed: a vulnerable function OpenWarp calls (govulncheck symbol level). |
| High | A security advisory or security-related release note for macOS (or for no stated platform) touching a component OpenWarp implements. |
| Medium | A relevant client change (MASQUE, WireGuard, registration, keys, protocol selection, DNS, proxy, routing, installer) in a macOS release note; a newer official macOS release than the one OpenWarp was studied from; a vulnerable package OpenWarp imports without calling the vulnerable code; a monitored source that changed format. |
| Low | Informational: other platforms, features OpenWarp does not have, module-only vulnerabilities, blog posts without protocol content. |

| Impact | Meaning |
|---|---|
| Confirmed affected | Reachable vulnerable code (govulncheck). Nothing upstream is ever "confirmed" for OpenWarp without that. |
| Potentially affected | OpenWarp implements comparable behaviour; someone has to check. |
| Insufficient evidence | The official client changed something in an area OpenWarp implements; its code is closed, so whether OpenWarp shares the old behaviour is unknown. |
| Not applicable | Another platform only, or a feature OpenWarp does not implement (Zero Trust, MDM, Lock WARP, Gateway, diagnostics...). |

The rules are in `tools/upstream-monitor/classify.go`: each OpenWarp component has a pattern, its code paths and
its tests, and each issue lists them. A fix in the official client is never assumed to be a bug in OpenWarp: the
issue asks the maintainer to identify the subsystem, check OpenWarp's equivalent, and only then test or fix.

Only Medium and above (and not "Not applicable") get an issue; everything else is in the run summary.

## Issues and de-duplication

- Every issue body carries hidden markers: `upstream-monitor:id=…` (the finding's stable id: advisory id, CVE,
  canonical changelog URL, `cf-macos-ga-newer-than:<studied version>`, Go vulnerability id), `key=…` (aliases:
  a GHSA's CVE, the id of each quoted release-note sentence) and `evidence=…` (a hash of the evidence).
- A finding whose id or alias is already in an issue never opens a second one. A release-note sentence that
  is already quoted in an issue is not quoted again (a release repeats its beta's notes).
- When the evidence changes, the monitor comments on the issue and updates the marker. A **closed** issue gets
  the comment but is never reopened. The monitor never closes issues: close them by hand.
- Only markers in issues written by `github-actions[bot]` are trusted, so an issue opened by someone else
  cannot suppress an alert.
- At most 5 new issues per run, most severe first; the rest wait for the next run and are listed as deferred.
  On a GitHub rate limit the monitor stops writing for that run.
- A source that is down (timeouts, 5xx, 429) is retried three times and then reported as **unavailable** in
  the summary, without an issue. A source that answers with something the monitor cannot read (404, a changed
  format) is **format changed** and gets one issue, because changes would otherwise go unnoticed.

Labels: `upstream-monitoring` on all of them, plus `security`, `compatibility`, `dependencies` and
`needs-investigation` as appropriate. The monitor creates any that are missing.

## Reading the report

Each run's job summary (Actions → Upstream monitor → the run) shows: the last successful run, every source and
its state, the studied and latest official macOS versions, findings with what happened to each issue,
informational findings (collapsed), govulncheck results (or "not run"), security-sensitive module updates, the
offline test results, open security issues from the monitor, and recommended next actions. The full report,
including every informational finding, is attached as the `upstream-monitor-report` artifact for 14 days.
Nothing is committed to the repository.

Run it by hand: Actions → Upstream monitor → Run workflow (tick *Dry run* to write nothing). Locally, read-only:

```sh
go run ./tools/upstream-monitor -dry-run   # prints the report; no token, nothing written
```

## Compatibility tests

Offline, deterministic, part of `go test ./...`:

| Test | Covers |
|---|---|
| `internal/api` `TestAPICompat*` | Every field OpenWarp reads, from recorded response shapes (`internal/api/testdata/compat`, synthetic values); unknown fields ignored; a type change is a named error; HTML error pages, captive portals, truncated JSON, 401, 429 and 5xx; no identity fallback on 429/5xx; the caller's deadline; TLS verification and SNI unchanged. |
| `internal/tunnel` `TestMasqueCompat*` | CONNECT-IP refused by the edge; a silent edge within the deadline; a tunnel dropped by the edge is reported (what triggers a reconnect). |
| `internal/daemon` `TestEndpointCandidatesCompat` | Edge addresses and port order for MASQUE and WireGuard, API-provided ports, the override, no peers. |
| `internal/daemon` `TestKeyEnrollmentWithoutPeersIsAnErrorNotACrash` | A key enrollment answer without a usable peer. |
| Existing | `TestEndToEndProxyModeOverMasque` (register, enroll, connect, proxy traffic, reconnect, disconnect against a mock API and edge), `TestMasqueConnectIP`, `TestWireGuardWithReservedBytes`, the registration and envelope tests. |

When Cloudflare changes a response, add a redacted fixture of the new shape first, then change the client in a
reviewed pull request.

## Live compatibility (manual)

`live-compat.yml` connects to the real service, so it only runs when started by hand and approved. It runs
the daemon **unprivileged in Local proxy mode** (user-space network stack): no root, no routes, no DNS changes on
the runner. A protocol passes only if `https://www.cloudflare.com/cdn-cgi/trace`, fetched through the proxy,
reports `warp=on` (or `plus`). It never prints the state, token, keys, registration id or addresses.

Setup (once, by the maintainer):

1. Create a **dedicated test registration**, not your own, in a new Terminal window (the changed `HOME` keeps
   it apart from your real state):

   ```sh
   export HOME=$(mktemp -d) OPENWARP_SOCKET=/tmp/ow-test.sock
   ./build/openwarp daemon &              # unprivileged, proxy mode only
   ./build/openwarp registration new      # accept the Terms of Service
   base64 -i "$HOME/Library/Application Support/openwarp/state.json" | pbcopy
   kill %1; rm -rf "$HOME"; exit
   ```

2. Create the environment: Settings → Environments → New environment `live-tests`, add yourself as a required
   reviewer, and limit it to the `main` branch.
3. Add the copied text as the secret `OPENWARP_LIVE_STATE` of that environment.

Each run enrolls the key for the protocol under test on that test registration (as the official client does
when the protocol changes); it affects only the test registration. Not covered anywhere in CI, because they
change the machine's networking: the root modes (utun routes, `networksetup` DNS, the `:53` stub resolver) and
`service install`.

## Boundaries

The monitor reads public documents and reports. It does not change code, settings, routes or DNS; does not
download or run anything from upstream; has no `os/exec` (checked by `TestMonitorRunsNoCommands`); quotes
upstream text only after neutralising mentions, issue references, HTML and its own marker syntax; links only to
an allow-list of official hosts; and sends the GitHub token only to `api.github.com`. Its workflow has
`contents: read`, `issues: write` and `actions: read`, pinned actions, and no pull request or push trigger
(`TestWorkflowSafety`). Any fix it prompts goes through a normal branch, tests and a reviewed pull request.

## Maintaining the monitor

- **A source changed format** (issue "Upstream monitor: the source … changed"): update its parser in
  `tools/upstream-monitor/sources.go` and the fixture in `tools/upstream-monitor/testdata/`.
- **Too many or too few findings**: adjust the patterns in `classify.go` and add a test case with the sentence.
- **After studying a new official release**: update `api.MacClientVersion`; the monitor uses it as the
  baseline, so the "newer official macOS client" issue stops recurring.
- Pinned versions (`GOVULNCHECK_VERSION`, action SHAs) are updated by Dependabot or by hand like every other
  workflow.
