## What changed

<!-- What the PR does, for a reviewer who has not seen the branch. Link issues with "Closes #N". -->

## Why

<!-- The problem or need behind the change. -->

## Affected areas

<!-- e.g. daemon/engine, CLI, API client, tunnel, sysnet, SwiftUI app, CI. -->

## Tests

- Added or updated: <!-- which tests, and what behaviour they pin down -->
- Executed locally: <!-- commands you ran, e.g. go test ./... -race; xcodebuild test -scheme OpenWarp -->
- Results: <!-- pass counts; anything skipped and why -->

## Risks and breaking changes

<!-- What could go wrong; any change to the CLI JSON contract, state.json or the LaunchDaemon. -->

## Screenshots

<!-- UI changes: before and after. -->

## Checklist

- [ ] Tests cover the change (regression test for a bug fix), and nothing was skipped or weakened
- [ ] `gofmt -l .`, `go vet ./...` and the test suites pass locally
- [ ] `CHANGELOG.md` updated for user-visible changes
- [ ] No secrets, real registrations, keys or license keys in code, fixtures, logs or screenshots
- [ ] Tests stay offline and need no root (no real Cloudflare calls, routes or DNS changes)
