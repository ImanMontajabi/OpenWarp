package main

// Synthetic daemon responses for the CLI tests and the JSON contract. Every
// ID, key, address and license here is made up (documentation ranges, all-zero
// keys); none belongs to a real registration.

import (
	"time"

	"github.com/ImanMontajabi/OpenWarp/internal/api"
	"github.com/ImanMontajabi/OpenWarp/internal/buildinfo"
	"github.com/ImanMontajabi/OpenWarp/internal/daemon"
	"github.com/ImanMontajabi/OpenWarp/internal/dnsproxy"
	"github.com/ImanMontajabi/OpenWarp/internal/state"
	"github.com/ImanMontajabi/OpenWarp/internal/tunnel"
)

var fixtureTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func fixtureStatusConnected() daemon.Status {
	return daemon.Status{
		Status:      daemon.StatusConnected,
		Mode:        state.ModeWarp,
		ModeLabel:   state.ModeWarp.Label(),
		Protocol:    state.ProtoMasque,
		Registered:  true,
		AccountType: "free",
		Since:       fixtureTime,
		Interface:   "utun9",
		InterfaceV4: "172.16.0.2",
		InterfaceV6: "2001:db8::2",
		DNSProtocol: "udp",
		Tunnel: &tunnel.Stats{
			Protocol: "masque", Endpoint: "192.0.2.10:443",
			TxBytes: 123456, RxBytes: 654321, TxPackets: 100, RxPackets: 200,
			LastHandshake: fixtureTime, HandshakeRTT: "42ms", TLS: "TLS 1.3, X25519MLKEM768",
		},
		DNS:     &dnsproxy.Stats{Queries: 10, Fallback: 2, Failures: 1},
		Network: "Wi-Fi",
		Version: buildinfo.Version,
		// More than the current transport: an earlier transport of this connection carried traffic too.
		Usage: &daemon.Usage{TxBytes: 5_123_456, RxBytes: 48_654_321, Since: fixtureTime},
		Protection: daemon.Protection{
			State: daemon.ProtVerified, KillSwitch: daemon.KSProtecting, IPv6: "blocked", DNS: "tunnel",
			Verification: fixtureVerification(),
		},
	}
}

func fixtureVerification() *daemon.Verification {
	return &daemon.Verification{Result: "verified", At: fixtureTime, Checks: []daemon.Check{
		{Name: "tunnel", Status: "pass", Detail: "masque via 192.0.2.10:443"},
		{Name: "ipv4_route", Status: "pass", Detail: "IPv4 goes through utun9"},
		{Name: "ipv6_route", Status: "pass", Detail: "IPv6 is blocked (the tunnel has no IPv6 address)"},
		{Name: "dns", Status: "pass", Detail: "system DNS: 192.0.2.53"},
		{Name: "kill_switch", Status: "pass", Detail: "pf rules loaded and pf enabled"},
		{Name: "cloudflare", Status: "pass", Detail: "Cloudflare reports warp=on (data centre XXX)"},
	}}
}

func fixtureStatusRetrying() daemon.Status {
	return daemon.Status{
		Status:      daemon.StatusConnecting,
		Reason:      "retrying in 4s",
		Error:       "dial 192.0.2.10:443: timeout",
		Mode:        state.ModeProxy,
		ModeLabel:   state.ModeProxy.Label(),
		Protocol:    state.ProtoWireGuard,
		Registered:  true,
		AccountType: "unlimited",
		WarpPlus:    true,
		DNSProtocol: "none",
		Network:     "Ethernet",
		Version:     buildinfo.Version,
		Usage:       &daemon.Usage{TxBytes: 2048, RxBytes: 4096, Since: fixtureTime},
		Protection: daemon.Protection{State: daemon.ProtConnecting, KillSwitch: daemon.KSUnavailable,
			KillSwitchDetail: "in Local proxy mode only apps that use the proxy are tunnelled; the system network is not changed"},
	}
}

func fixtureStatusUnregistered() daemon.Status {
	return daemon.Status{
		Status:      daemon.StatusDisconnected,
		Mode:        state.ModeWarp,
		ModeLabel:   state.ModeWarp.Label(),
		Protocol:    state.ProtoMasque,
		DNSProtocol: "udp",
		Version:     buildinfo.Version,
		Protection:  daemon.Protection{State: daemon.ProtUnprotected, KillSwitch: daemon.KSOff},
	}
}

func fixtureRegistration() daemon.RegistrationView {
	return daemon.RegistrationView{
		ID:          "00000000-0000-4000-8000-000000000001",
		AccountID:   "00000000-0000-4000-8000-000000000002",
		AccountType: "free",
		PremiumData: 0,
		Quota:       0,
		License:     "TEST0000-TEST0000-TEST0000",
		PublicKey:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		KeyType:     "curve25519",
		InterfaceV4: "172.16.0.2",
		InterfaceV6: "2001:db8::2",
		Created:     "2026-01-02T03:04:05Z",
		Peer: &api.Peer{
			PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			Endpoint:  api.Endpoint{V4: "192.0.2.10:0", V6: "[2001:db8::10]:0", Host: "engage.example.invalid:2408"},
		},
	}
}

func fixtureDevices() []api.Device {
	return []api.Device{
		{ID: "00000000-0000-4000-8000-000000000001", Type: "macOS", Model: "Mac16,8", Name: "", Created: "2026-01-02T03:04:05Z", Activated: "2026-01-02T03:04:05Z", Active: true, Role: "parent"},
		{ID: "00000000-0000-4000-8000-000000000003", Type: "Android", Model: "PC", Name: "Old laptop", Created: "2025-06-07T08:09:10Z", Activated: "2025-06-07T08:09:10Z", Active: false, Role: "child"},
	}
}
