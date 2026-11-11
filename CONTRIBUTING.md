# Contributing to OpenWarp

Thanks for helping. OpenWarp is maintained by one person, so small, focused pull requests with tests are the
fastest way to get a change in.

## Ground rules

- **Every change reaches `main` through a pull request.** Direct pushes, force pushes and deleting `main` (and
  `release`) are blocked by repository rulesets, and every required CI check must pass before a PR can be merged.
- **Every meaningful change comes with tests.** A new feature gets tests that pin down its behaviour; a bug fix
  gets a regression test that fails without the fix. Write the test first when you can. Tests must check
  observable behaviour (results, errors, edge cases), not just raise coverage.
- **Never weaken a test to make CI pass.** Do not skip, disable or loosen a failing test without explaining why
  in the PR and getting agreement first.
- **Tests stay offline and unprivileged.** They must not contact Cloudflare, create or change real
  registrations, need root, or change routes or DNS. Use the mock API and mock edge in
  `internal/daemon/e2e_test.go` and `internal/tunnel/*_test.go`, and synthetic keys and IDs only.
- **Never commit secrets.** No `state.json`, tokens, private keys, license keys or real device IDs, in code,
  fixtures, logs or screenshots.

## Branches and releases

- **`main`** and **`release`** are the only permanent branches; neither is ever deleted.
- **`main`** is the development branch: it holds integrated, reviewed work. Feature branches start from the latest
  `main` and come back through squash-merged pull requests.
- **Temporary branches** (`feat/…`, `fix/…`, `test/…`, `docs/…`, `ci/…`, `refactor/…`) live only while their pull
  request is open. Once a pull request is merged into `main` and nothing else depends on the branch (no open pull
  request based on it, no branch built on top of it), it is deleted, remotely (GitHub does this automatically) and
  locally. Branches are deleted after they reach `main`, not after the next release. A branch whose pull request was
  closed without merging, or whose state is unclear, is kept until the maintainer decides.
- **Completed features accumulate on `main`** until the maintainer decides to publish a version. If `main` then
  contains work that should not ship yet, it is not promoted as a whole; the maintainer decides how to proceed
  (finish or revert the work on `main` first).
- **`release`** holds what is ready to ship. It changes only through a pull request **from `main`** (merged with a
  merge commit, so the history of `main` stays intact), after the "Release candidate" workflow has checked the
  version, the changelog section, the third-party notices and the universal build. Pushes, force pushes and
  deletion are blocked for everyone.
- **Releases** are built from `release` only. After a main → release pull request is merged and the push
  checks on that commit have passed, the maintainer runs the "Release" workflow by hand on `release` with the
  version. It checks the version, changelog, release notes and required checks, builds the universal app, packages
  `OpenWarp-v<version>-macos-universal.dmg` (plus a zip and `SHA256SUMS.txt`), tests the DMG and a service
  install on the runner, and, after the maintainer approves the `release` environment, creates a **draft**
  GitHub release that names tag `v<version>` at that commit. No tag is pushed: GitHub creates it when the
  maintainer publishes the draft, which is a separate manual step. Version tags cannot be moved or deleted.

To prepare a release (maintainer): bump the version in `internal/buildinfo/buildinfo.go`, `build.sh` and
`FakeDaemon.version`; move the `[Unreleased]` notes to `## [x.y.z] - YYYY-MM-DD`; add the release notes in
`docs/releases/vx.y.z.md`; merge that to `main`; then open a pull request from `main` into `release`.

Build a DMG locally with `./build.sh && scripts/make-dmg.sh build/OpenWarp.app dist/OpenWarp.dmg` (Finder lays
out the window, so the first run asks to let your terminal control Finder; `OPENWARP_DMG_PLAIN=1` skips the
layout) and check it with `scripts/verify-dmg.sh dist/OpenWarp.dmg <version>`.

## Workflow

1. Open or pick an issue (for anything larger than a small fix).
2. Create a branch named for the change: `feat/…`, `fix/…`, `refactor/…`, `test/…`, `docs/…` or `ci/…`.
3. Write or update tests, then implement the change.
4. Run the checks locally (below) and review your own diff.
5. Commit with a clear message in the imperative mood (`Fix DNS restore after a crash`). Conventional prefixes
   such as `fix:` or `feat:` are welcome but not required.
6. Push and open a pull request. Fill in the template, including which tests you ran and their results, and
   before/after screenshots for UI changes.
7. Address CI failures and review comments. Merge conflicts with `main` are resolved with an ordinary merge of
   `main` into the branch, never by rewriting a pushed branch's history.
8. PRs are squash-merged once every required check is green **and the maintainer has approved the merge**.

**Maintainer approval is required for:** merging any pull request; deleting a branch other than through GitHub's
automatic deletion after a merge; promoting `main` to `release`; running the release workflow's publication steps,
creating tags, and publishing a GitHub release.

## Local checks

```sh
gofmt -l .                       # prints nothing when formatting is clean
go vet ./...
go mod tidy && git diff --exit-code go.mod go.sum
go test ./... -race -count=1
./build.sh                       # full build of the CLI and the app
```

For changes to the SwiftUI app (`ui/macos`), also run its tests. They need Xcode and
[XcodeGen](https://github.com/yonaskolb/XcodeGen) (`brew install xcodegen`):

```sh
scripts/test-app.sh              # unit, contract and snapshot tests (opens no windows)
scripts/test-app.sh ui           # plus the XCUITest UI tests (they drive the mouse and keyboard)
scripts/test-app.sh record       # re-record snapshot goldens after an intended visual change
```

`OpenWarp.xcodeproj` is generated from `project.yml` and not committed. UI tests run the app against an
in-process fake daemon (`ui/macos/FakeDaemon.swift`, Debug builds only), so they need no daemon or network.
Commit re-recorded snapshot PNGs only after reviewing the visual diff, and mention it in the PR.

CI also runs `staticcheck`, `govulncheck`, CodeQL (Go and Swift) and a secret scan; see `.github/workflows/`.

## Changelog

Add a line under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md) for any user-visible change.

## Code style

- Go: standard library first, `gofmt`, small packages. macOS-only code goes behind `//go:build darwin`.
- Swift: follow the existing structure in `ui/macos` and the UI rules in [CLAUDE.md](CLAUDE.md) (dark, flat,
  no placeholder values shown as live data, Reduce Motion respected through `\.owReduceMotion`). Give new
  interactive controls an `accessibilityIdentifier` so UI tests can find them.
- The CLI's `-j` JSON output is a contract with the app; change the Go structs and `ui/macos/Models.swift`
  together.

## License

By contributing you agree that your contribution is licensed under the [MIT License](LICENSE).
