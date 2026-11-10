#!/bin/sh
# Repository consistency checks (CI "Repository checks" job; safe to run locally).
set -eu
cd "$(dirname "$0")/.."
fail=0
err() { echo "::error::$*"; fail=1; }

# Project files every public release needs.
for f in README.md LICENSE CONTRIBUTING.md SECURITY.md CHANGELOG.md \
         .github/pull_request_template.md .github/CODEOWNERS .github/dependabot.yml \
         .github/ISSUE_TEMPLATE/bug_report.yml .github/ISSUE_TEMPLATE/feature_request.yml; do
  [ -s "$f" ] || err "missing or empty: $f"
done

# One version everywhere: the CLI and the app bundle.
cli=$(sed -n 's/^const Version = "\(.*\)"$/\1/p' internal/buildinfo/buildinfo.go)
app=$(sed -n 's/.*<key>CFBundleShortVersionString<\/key><string>\(.*\)<\/string>.*/\1/p' build.sh)
[ -n "$cli" ] || err "cannot read the version from internal/buildinfo/buildinfo.go"
[ "$cli" = "$app" ] || err "version mismatch: CLI $cli, app bundle (build.sh) $app"
# The UI tests' fake daemon reports the app's version once "installed".
fake=$(sed -n 's/^ *static let version = "\(.*\)"$/\1/p' ui/macos/FakeDaemon.swift)
[ "$cli" = "$fake" ] || err "version mismatch: CLI $cli, FakeDaemon.version $fake"
grep -q "^## \[Unreleased\]" CHANGELOG.md || err "CHANGELOG.md has no [Unreleased] section"

# JSON contract fixtures shared by the Go and Swift tests must be valid JSON.
for f in testdata/contract/*.json; do
  python3 -I -c 'import json,sys; json.load(open(sys.argv[1]))' "$f" || err "invalid JSON: $f"
done

# Never track local daemon state or key material.
if git ls-files | grep -E '(^|/)state\.json$|\.(pem|p12|key)$'; then
  err "tracked file looks like local state or key material (listed above)"
fi

[ "$fail" = 0 ] && echo "Repository checks passed (version $cli)."
exit "$fail"
