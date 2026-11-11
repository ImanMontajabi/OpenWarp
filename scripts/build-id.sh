#!/bin/sh
# Prints the build identifier build.sh stamps into the CLI/daemon (internal/buildinfo.Build) and the app
# (Info.plist key OpenWarpBuild): "dev.<commit>" for a development build, with ".dirty" when tracked files
# differ from that commit, "dev" outside a git checkout, and nothing for a release build
# (OPENWARP_RELEASE=1, set only by release.yml and release-candidate.yml). The full version is
# <Version>+<build id>, e.g. 0.1.0+dev.1a2b3c4, so a development build never looks like a release.
set -eu
if [ "${OPENWARP_RELEASE:-}" = 1 ]; then
  exit 0
fi
cd "$(dirname "$0")/.."
if rev=$(git rev-parse --short=7 HEAD 2>/dev/null); then
  if git diff --quiet HEAD -- 2>/dev/null; then
    echo "dev.$rev"
  else
    echo "dev.$rev.dirty"
  fi
else
  echo dev
fi
