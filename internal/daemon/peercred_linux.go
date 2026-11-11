//go:build linux

package daemon

import "golang.org/x/sys/unix"

// peerCred reads the connecting process's credentials from the kernel (SO_PEERCRED). Linux is not a
// supported platform; this keeps the tests meaningful on Linux CI.
func peerCred(fd int) (Peer, error) {
	cr, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return Peer{}, err
	}
	return Peer{UID: cr.Uid, PID: int(cr.Pid)}, nil
}
