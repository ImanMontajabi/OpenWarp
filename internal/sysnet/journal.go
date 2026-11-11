package sysnet

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
)

// journal records what Apply changed, on disk, so a daemon that crashed (or was killed) can undo it on its
// next start: the routes it added through the physical gateway outlive the process (the utun routes vanish
// with the interface), and so do the DNS servers it set.
type journal struct {
	Routes [][]string          `json:"routes"` // `route` arguments that delete what was added
	DNS    map[string][]string `json:"dns"`    // network service -> previous DNS servers (empty: automatic)
}

var reRouteArg = regexp.MustCompile(`^[-A-Za-z0-9.:/%]{1,64}$`)

// validate accepts only what Apply itself writes: `route -n delete …` with plain address arguments, and DNS
// servers that are IP addresses. The file is root-owned (0600), but it is still never trusted blindly.
func (j *journal) validate() error {
	for _, r := range j.Routes {
		if len(r) < 4 || r[0] != "-n" || r[1] != "delete" {
			return fmt.Errorf("journal: unexpected route command %q", r)
		}
		for _, a := range r {
			if !reRouteArg.MatchString(a) {
				return fmt.Errorf("journal: unexpected route argument %q", a)
			}
		}
	}
	for svc, servers := range j.DNS {
		if svc == "" || len(svc) > 128 {
			return fmt.Errorf("journal: bad network service %q", svc)
		}
		for _, s := range servers {
			if _, err := netip.ParseAddr(s); err != nil {
				return fmt.Errorf("journal: bad DNS server %q", s)
			}
		}
	}
	return nil
}

func writeJournal(path string, j *journal) error {
	if path == "" {
		return nil
	}
	b, err := json.Marshal(j)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readJournal(path string) (*journal, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var j journal
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, fmt.Errorf("journal: %w", err)
	}
	return &j, j.validate()
}

// ErrNoJournal means there was nothing to recover.
var ErrNoJournal = errors.New("no network changes to undo")
