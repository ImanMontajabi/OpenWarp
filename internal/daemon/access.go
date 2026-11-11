package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/user"
	"slices"
	"strconv"
)

// Access decides who may use the control socket.
//
// The root service's socket accepts connections from every local user (mode 0666), because the app and the
// CLI run as the logged-in user. What a connection may do is decided for each request from the connecting
// process's credentials, which the kernel reports for unix sockets (LOCAL_PEERCRED on macOS) and which a
// client cannot choose:
//   - any local user: GET /v1/status, read-only;
//   - root, the users in UIDs (the service records the user who installed it) and, with Admins, members of
//     the admin group: everything else. That covers connecting and disconnecting, every setting (including
//     the kill switch, the mode and the split-tunnel lists), verification, and the registration and its
//     license.
//
// A daemon that does not run as root (proxy mode) admits only its own user and root, and its socket is 0600.
// Administrators can already change the system through sudo, so admitting them grants nothing new.
type Access struct {
	UIDs   []uint32
	Admins bool
	// groups returns a user's group IDs, including memberships the directory service resolves (os/user
	// calls getgrouplist); tests replace it.
	groups func(uid uint32) ([]uint32, error)
}

// adminGID is macOS's "admin" group: the users who may use sudo.
const adminGID = 80

// DefaultAccess is root, administrators and nobody else for a root daemon, and the daemon's own user for
// one that is not root.
func DefaultAccess() Access {
	if uid := os.Geteuid(); uid != 0 {
		return Access{UIDs: []uint32{uint32(uid)}}
	}
	return Access{Admins: true}
}

// Peer is the process on the other end of a control-socket connection, as the kernel reports it.
type Peer struct {
	UID uint32
	PID int // 0 when unknown
}

type peerKey struct{}

// ErrForbidden is returned to clients that may not perform a request.
var ErrForbidden = errors.New("not allowed")

// Allows reports whether the peer may perform requests beyond reading the status.
func (a Access) Allows(p Peer) error {
	if p.UID == 0 || slices.Contains(a.UIDs, p.UID) {
		return nil
	}
	if a.Admins {
		groups := a.groups
		if groups == nil {
			groups = userGroups
		}
		gs, err := groups(p.UID)
		if err == nil && slices.Contains(gs, adminGID) {
			return nil
		}
	}
	return fmt.Errorf("%w: user %d may only read the status of the OpenWarp service; root, administrators and the user who installed the service can control it (reinstall the service from your account to use it)", ErrForbidden, p.UID)
}

func userGroups(uid uint32) ([]uint32, error) {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return nil, err
	}
	ids, err := u.GroupIds()
	if err != nil {
		return nil, err
	}
	out := make([]uint32, 0, len(ids))
	for _, id := range ids {
		if n, err := strconv.ParseUint(id, 10, 32); err == nil {
			out = append(out, uint32(n))
		}
	}
	return out, nil
}

// public lists the requests any local user may make.
func public(r *http.Request) bool { return r.Method == http.MethodGet && r.URL.Path == "/v1/status" }

// Wrap enforces the policy in front of h. A request whose peer is unknown (no credentials on the
// connection) is refused unless it is public.
func (a Access) Wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if public(r) {
			h.ServeHTTP(w, r)
			return
		}
		p, ok := r.Context().Value(peerKey{}).(Peer)
		var err error
		if !ok {
			err = fmt.Errorf("%w: cannot identify the connecting process", ErrForbidden)
		} else {
			err = a.Allows(p)
		}
		if err != nil {
			// %q: the method and path come from the client and must not be able to forge log lines.
			log.Printf("control: refused %q %q from uid %d (pid %d)", r.Method, r.URL.Path, p.UID, p.PID)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		h.ServeHTTP(w, r)
	})
}

// connContext attaches the peer's credentials to every request on the connection.
func connContext(ctx context.Context, c net.Conn) context.Context {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return ctx
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return ctx
	}
	var p Peer
	var perr error
	if err := raw.Control(func(fd uintptr) { p, perr = peerCred(int(fd)) }); err != nil || perr != nil {
		return ctx
	}
	return context.WithValue(ctx, peerKey{}, p)
}
