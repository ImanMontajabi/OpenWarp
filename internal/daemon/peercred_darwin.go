//go:build darwin

package daemon

import "golang.org/x/sys/unix"

// peerCred reads the connecting process's credentials from the kernel (LOCAL_PEERCRED, LOCAL_PEERPID).
func peerCred(fd int) (Peer, error) {
	cr, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return Peer{}, err
	}
	pid, _ := unix.GetsockoptInt(fd, unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	return Peer{UID: cr.Uid, PID: pid}, nil
}
