// Package state persists the registration, keys and user settings.
// Settings mirror what `warp-cli settings list` shows on the official client.
package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/ImanMontajabi/OpenWarp/internal/api"
	"github.com/ImanMontajabi/OpenWarp/internal/keys"
)

type Mode string

const (
	ModeWarp       Mode = "warp"        // tunnel + system DNS -> Cloudflare (UDP) through tunnel
	ModeWarpDoH    Mode = "warp+doh"    // tunnel + local DNS proxy using DoH
	ModeWarpDoT    Mode = "warp+dot"    // tunnel + local DNS proxy using DoT
	ModeDoH        Mode = "doh"         // no tunnel, DNS only over DoH ("1.1.1.1" mode)
	ModeDoT        Mode = "dot"         // no tunnel, DNS only over DoT
	ModeProxy      Mode = "proxy"       // tunnel exposed as local SOCKS5/HTTP proxy, no root
	ModeTunnelOnly Mode = "tunnel_only" // tunnel, DNS untouched
)

var AllModes = []Mode{ModeWarp, ModeWarpDoH, ModeWarpDoT, ModeDoH, ModeDoT, ModeProxy, ModeTunnelOnly}

func (m Mode) Valid() bool {
	for _, x := range AllModes {
		if x == m {
			return true
		}
	}
	return false
}
func (m Mode) HasTunnel() bool { return m != ModeDoH && m != ModeDoT }
func (m Mode) UsesTun() bool   { return m.HasTunnel() && m != ModeProxy }
func (m Mode) Label() string {
	switch m {
	case ModeWarp:
		return "Traffic and DNS (UDP)"
	case ModeWarpDoH:
		return "Traffic and DNS (HTTPS)"
	case ModeWarpDoT:
		return "Traffic and DNS (TLS)"
	case ModeDoH:
		return "DNS only (HTTPS)"
	case ModeDoT:
		return "DNS only (TLS)"
	case ModeProxy:
		return "Local proxy (SOCKS5/HTTP)"
	case ModeTunnelOnly:
		return "Traffic only"
	}
	return string(m)
}

type Protocol string

const (
	ProtoMasque    Protocol = "masque"
	ProtoWireGuard Protocol = "wireguard"
)

type Families string

const (
	FamiliesOff     Families = "off"
	FamiliesMalware Families = "malware"
	FamiliesFull    Families = "full"
)

type SplitMode string

const (
	SplitExclude SplitMode = "exclude"
	SplitInclude SplitMode = "include"
)

// Default exclude list taken from the official client's "(api defaults)
// Exclude mode" list.
var DefaultExcludes = []string{
	"10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
	"192.168.0.0/16", "224.0.0.0/24", "240.0.0.0/4", "239.255.255.250/32", "255.255.255.255/32",
	"fe80::/10", "fd00::/8", "ff01::/16", "ff02::/16", "ff03::/16", "ff04::/16", "ff05::/16", "fc00::/7",
	"17.249.0.0/16", "17.252.0.0/16", "17.57.144.0/22", "17.188.128.0/18", "17.188.20.0/23",
	"2620:149:a44::/48", "2403:300:a42::/48", "2403:300:a51::/48", "2a01:b740:a42::/48",
}

// Default Local Domain Fallback suffixes from the official client.
var DefaultFallbackDomains = []string{
	"corp", "domain", "home", "home.arpa", "host", "internal", "intranet", "invalid",
	"lan", "local", "localdomain", "localhost",
}

type Settings struct {
	Mode             Mode      `json:"mode"`
	Protocol         Protocol  `json:"protocol"`
	AlwaysOn         bool      `json:"always_on"` // reconnect automatically after restart
	Families         Families  `json:"families"`
	ProxyPort        int       `json:"proxy_port"`
	EndpointOverride string    `json:"endpoint_override,omitempty"` // ip:port
	MTU              int       `json:"mtu"`
	SplitMode        SplitMode `json:"split_mode"`
	SplitIPs         []string  `json:"split_ips"`
	FallbackDomains  []string  `json:"fallback_domains"`
	TrustedSSIDs     []string  `json:"trusted_ssids"`
	DisableWiFi      bool      `json:"disable_wifi"`
	DisableEthernet  bool      `json:"disable_ethernet"`
	PostQuantum      bool      `json:"post_quantum"`
}

func DefaultSettings() Settings {
	return Settings{
		Mode:            ModeWarp,
		Protocol:        ProtoMasque,
		Families:        FamiliesOff,
		ProxyPort:       40000,
		MTU:             1280,
		SplitMode:       SplitExclude,
		SplitIPs:        append([]string(nil), DefaultExcludes...),
		FallbackDomains: append([]string(nil), DefaultFallbackDomains...),
		PostQuantum:     true,
	}
}

type State struct {
	Registration *api.Registration `json:"registration,omitempty"`
	WireGuardKey *keys.WireGuard   `json:"wireguard_key,omitempty"`
	ECDSAKey     string            `json:"ecdsa_key,omitempty"`
	// ActiveKeyType is the key type currently enrolled on the registration.
	ActiveKeyType string `json:"active_key_type,omitempty"`
	// Per-protocol peer configs captured when each key was enrolled.
	WireGuardConfig *api.Config `json:"wireguard_config,omitempty"`
	MasqueConfig    *api.Config `json:"masque_config,omitempty"`
	Settings        Settings    `json:"settings"`
	ToSAccepted     bool        `json:"tos_accepted"`
}

type Store struct {
	mu   sync.Mutex
	path string
	S    State
}

func DefaultDir() string {
	if os.Geteuid() == 0 {
		return "/Library/Application Support/openwarp"
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "Application Support", "openwarp")
}

// legacyDirName is the state directory name used before the rename to openwarp.
const legacyDirName = "cwarp"

// migrateLegacy copies state.json from the pre-rename sibling directory
// (".../cwarp") into dir when dir has none yet. The old file is left in place.
func migrateLegacy(dir string) {
	dst := filepath.Join(dir, "state.json")
	if _, err := os.Stat(dst); !errors.Is(err, os.ErrNotExist) || filepath.Base(dir) != "openwarp" {
		return
	}
	b, err := os.ReadFile(filepath.Join(filepath.Dir(dir), legacyDirName, "state.json"))
	if err != nil {
		return
	}
	if os.WriteFile(dst+".tmp", b, 0o600) == nil {
		os.Rename(dst+".tmp", dst)
	}
}

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	migrateLegacy(dir)
	st := &Store{path: filepath.Join(dir, "state.json"), S: State{Settings: DefaultSettings()}}
	b, err := os.ReadFile(st.path)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &st.S); err != nil {
		return nil, err
	}
	if st.S.Settings.ProxyPort == 0 {
		st.S.Settings.ProxyPort = 40000
	}
	if st.S.Settings.MTU == 0 {
		st.S.Settings.MTU = 1280
	}
	if st.S.Settings.Mode == "" {
		st.S.Settings.Mode = ModeWarp
	}
	if st.S.Settings.Protocol == "" {
		st.S.Settings.Protocol = ProtoMasque
	}
	return st, nil
}

func (s *Store) Lock()   { s.mu.Lock() }
func (s *Store) Unlock() { s.mu.Unlock() }

// Save must be called with the lock held.
func (s *Store) Save() error {
	b, err := json.MarshalIndent(&s.S, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
