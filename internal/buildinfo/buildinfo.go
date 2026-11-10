// Package buildinfo holds the OpenWarp version shared by the CLI, the daemon
// (reported in its status so the app can spot an outdated service) and the app
// bundle (scripts/check-repo.sh keeps build.sh in step with it).
package buildinfo

// Version is the OpenWarp release version.
const Version = "0.1.0"
