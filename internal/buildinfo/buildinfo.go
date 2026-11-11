// Package buildinfo holds the OpenWarp version shared by the CLI, the daemon
// (reported in its status so the app can spot an outdated service) and the app
// bundle (scripts/check-repo.sh keeps build.sh in step with it).
package buildinfo

import (
	"regexp"
	"runtime/debug"
)

// Version is the OpenWarp release version.
const Version = "0.1.0"

// Build identifies a development build. build.sh sets it with
// -ldflags "-X github.com/ImanMontajabi/OpenWarp/internal/buildinfo.Build=<id>": "dev.<commit>[.dirty]" for
// development builds, empty for release builds (OPENWARP_RELEASE=1). A plain `go build` or `go run` keeps
// "dev", completed from the Go toolchain's VCS stamp when there is one.
var Build = "dev"

var reBuild = regexp.MustCompile(`^[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*$`)

// Full is the version that identifies this exact build: Version for a release build, otherwise
// Version+Build in semver build-metadata form ("0.1.0+dev.1a2b3c4"), which never compares equal to a
// release. The daemon reports it and the app compares it with its own bundled CLI's.
func Full() string { return full(Build, vcsStamp) }

// IsRelease reports whether this is a release build.
func IsRelease() bool { return Build == "" }

func full(build string, stamp func() (string, bool)) string {
	if build == "" {
		return Version
	}
	if build == "dev" {
		if rev, modified := stamp(); rev != "" {
			build += "." + rev
			if modified {
				build += ".dirty"
			}
		}
	}
	if !reBuild.MatchString(build) {
		build = "dev.invalid"
	}
	return Version + "+" + build
}

// vcsStamp returns the short commit and the modified flag the Go toolchain embeds (`go build` in a git
// checkout); nothing in tests or builds without VCS information.
func vcsStamp() (string, bool) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", false
	}
	var rev string
	var modified bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if len(rev) > 7 {
		rev = rev[:7]
	}
	return rev, modified
}
