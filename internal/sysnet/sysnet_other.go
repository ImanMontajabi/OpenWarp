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
}

type Applied struct{}

var errUnsupported = errors.New("system tunnel configuration is only implemented for macOS; use proxy mode")

func DefaultGateway(bool) (Gateway, error)        { return Gateway{}, errUnsupported }
func Apply(TunConfig) (*Applied, error)           { return nil, errUnsupported }
func (a *Applied) Undo()                          {}
func SetSystemDNS([]netip.Addr) (*Applied, error) { return nil, errUnsupported }
func CurrentResolvers() []netip.Addr              { return nil }
func NetworkKind() (string, string)               { return "", "" }
