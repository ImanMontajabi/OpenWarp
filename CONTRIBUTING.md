# Contributing to OpenWarp

Thanks for helping. OpenWarp is maintained by one person, so small, focused pull requests with tests are the
fastest way to get a change in.

## Ground rules

- **Every change reaches `main` through a pull request.** Direct pushes, force pushes and deleting `main` are
  blocked by a repository ruleset, and every required CI check must pass before a PR can be merged.
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

## Workflow

1. Open or pick an issue (for anything larger than a small fix).
2. Create a branch named for the change: `feat/…`, `fix/…`, `refactor/…`, `test/…`, `docs/…` or `ci/…`.
3. Write or update tests, then implement the change.
4. Run the checks locally (below) and review your own diff.
5. Commit with a clear message in the imperative mood (`Fix DNS restore after a crash`). Conventional prefixes
   such as `fix:` or `feat:` are welcome but not required.
6. Push and open a pull request. Fill in the template, including which tests you ran and their results, and
   before/after screenshots for UI changes.
7. Address CI failures and review comments. PRs are squash-merged once every required check is green.

## Local checks

```sh
gofmt -l .                       # prints nothing when formatting is clean
go vet ./...
go mod tidy && git diff --exit-code go.mod go.sum
go test ./... -race -count=1
./build.sh                       # full build of the CLI and the app
```

CI also runs `staticcheck`, `govulncheck` and a secret scan; see `.github/workflows/`.

## Changelog

Add a line under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md) for any user-visible change.

## Code style

- Go: standard library first, `gofmt`, small packages. macOS-only code goes behind `//go:build darwin`.
- Swift: follow the existing structure in `ui/macos` and the UI rules in [CLAUDE.md](CLAUDE.md) (dark, flat,
  no placeholder values shown as live data, Reduce Motion respected).
- The CLI's `-j` JSON output is a contract with the app; change the Go structs and `ui/macos/Models.swift`
  together.

## License

By contributing you agree that your contribution is licensed under the [MIT License](LICENSE).
