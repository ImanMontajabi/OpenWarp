//go:build !darwin && !linux

package daemon

import "errors"

// peerCred is unavailable here: every request but the status is refused.
func peerCred(int) (Peer, error) {
	return Peer{}, errors.New("peer credentials are not supported on this platform")
}
