//go:build !darwin

package sysnet

import (
	"errors"
	"net/netip"
)

type Gateway struct {
	Addr  netip.Addr
	Iface string
}

type TunConfig struct {
	Iface     string
	V4, V6    netip.Addr
	MTU       int
	Endpoint  netip.Addr
	SplitMode string
	Split     []netip.Prefix
	DNS       []netip.Addr
	Journal   string
}

const (
	IPv6Tunnel  = "tunnel"
	IPv6Blocked = "blocked"
	IPv6System  = "system"
)

type Applied struct{}

type Route struct {
	Iface  string
	Reject bool
}

var errUnsupported = errors.New("system tunnel configuration is only implemented for macOS; use proxy mode")

func DefaultGateway(bool) (Gateway, error)                { return Gateway{}, errUnsupported }
func Apply(TunConfig) (*Applied, error)                   { return nil, errUnsupported }
func (a *Applied) Undo()                                  {}
func (a *Applied) IPv6() string                           { return "" }
func SetSystemDNS([]netip.Addr, string) (*Applied, error) { return nil, errUnsupported }
func Recover(string) error                                { return ErrNoJournal }
func RouteTo(netip.Addr) (Route, bool, error)             { return Route{}, false, errUnsupported }
func SystemResolvers() ([]netip.Addr, error)              { return nil, errUnsupported }
func CurrentResolvers() []netip.Addr                      { return nil }
func NetworkKind() (string, string)                       { return "", "" }
