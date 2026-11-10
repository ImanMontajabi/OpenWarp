//go:build darwin

package daemon

import (
	"strings"
	"syscall"
)

// hardwareModel returns sysctl hw.model, e.g. "Mac16,8".
func hardwareModel() string {
	m, err := syscall.Sysctl("hw.model")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(m)
}
