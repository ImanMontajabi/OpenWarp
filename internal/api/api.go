// Package api is a client for the Cloudflare WARP consumer device API
// (api.cloudflareclient.com), the same service the official daemon's
// warp-api-client crate talks to.
package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	DefaultHost    = "api.cloudflareclient.com"
	DefaultVersion = "v0a4471"
	ClientVersion  = "a-6.35-4471"
	UserAgent      = "WARP for Android"
	// macOS client identity, used only for the registration POST so Cloudflare
	// lists the device as macOS. MacUserAgent and the "/v0/" API path are
	// strings found in the official macOS daemon; MacClientVersion follows the
	// "m-" prefix found there plus the official app version (exact format unverified).
	MacUserAgent     = "WARP for macOS"
	MacAPIVersion    = "v0"
	MacClientVersion = "m-2026.8.2115.0"

	KeyTypeWireGuard = "curve25519"
	KeyTypeMasque    = "secp256r1"
	TunTypeWireGuard = "wireguard"
	TunTypeMasque    = "masque"
)

// Fallback API addresses used by the official client when DNS for the API
// host fails ("ConsumerEndpointConfig { ips: {162.159.192.1, 2606:4700:d0::a29f:c001} }").
var FallbackAPIIPs = []string{"162.159.192.1", "2606:4700:d0::a29f:c001"}

type Account struct {
	ID                   string `json:"id"`
	AccountType          string `json:"account_type"`
	Created              string `json:"created,omitempty"`
	Updated              string `json:"updated,omitempty"`
	WarpPlus             bool   `json:"warp_plus"`
	PremiumData          int64  `json:"premium_data"`
	Quota                int64  `json:"quota"`
	License              string `json:"license"`
	ReferralCount        int    `json:"referral_count"`
	ReferralRenewalCount int    `json:"referral_renewal_countdown"`
	Role                 string `json:"role,omitempty"`
}

type Endpoint struct {
	V4    string `json:"v4"`
	V6    string `json:"v6"`
	Host  string `json:"host"`
	Ports []int  `json:"ports,omitempty"`
}

type Peer struct {
	PublicKey string   `json:"public_key"`
	Endpoint  Endpoint `json:"endpoint"`
}

type Config struct {
	ClientID  string `json:"client_id"`
	Peers     []Peer `json:"peers"`
	Interface struct {
		Addresses struct {
			V4 string `json:"v4"`
			V6 string `json:"v6"`
		} `json:"addresses"`
	} `json:"interface"`
	Services struct {
		HTTPProxy string `json:"http_proxy"`
	} `json:"services"`
}

type Registration struct {
	ID          string  `json:"id"`
	Type        string  `json:"type"`
	Model       string  `json:"model"`
	Name        string  `json:"name"`
	Key         string  `json:"key"`
	KeyType     string  `json:"key_type,omitempty"`
	TunnelType  string  `json:"tunnel_type,omitempty"`
	Account     Account `json:"account"`
	Config      Config  `json:"config"`
	Token       string  `json:"token,omitempty"`
	WarpEnabled bool    `json:"warp_enabled"`
	Waitlist    bool    `json:"waitlist_enabled"`
	Created     string  `json:"created"`
	Updated     string  `json:"updated"`
	Tos         string  `json:"tos"`
	Place       int     `json:"place"`
	Locale      string  `json:"locale"`
	Enabled     bool    `json:"enabled"`
	InstallID   string  `json:"install_id"`
}

type Device struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Model     string `json:"model"`
	Name      string `json:"name"`
	Created   string `json:"created"`
	Activated string `json:"activated"`
	Active    bool   `json:"active"`
	Role      string `json:"role"`
}

// Identity is how the client presents itself to the API: version path,
// User-Agent and CF-Client-Version. Cloudflare labels the device in the
// account's device list from this, not from the registration's "type" field.
type Identity struct {
	Version, UserAgent, ClientVersion string
}

var (
	AndroidIdentity = Identity{DefaultVersion, UserAgent, ClientVersion}
	MacIdentity     = Identity{MacAPIVersion, MacUserAgent, MacClientVersion}
)

type Client struct {
	// BaseURL overrides https://<Host> (like `warp-cli api endpoint`).
	BaseURL string
	Host    string
	// Identity used for every request (AndroidIdentity by default).
	Identity Identity
	HTTP     *http.Client
}

func New() *Client {
	c := &Client{Host: DefaultHost, Identity: AndroidIdentity}
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{ServerName: DefaultHost, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 10 * time.Second,
		// Try normal DNS first; if that fails, fall back to the known API
		// anycast IPs while keeping the SNI, like the official client does.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, addr)
			if err == nil {
				return conn, nil
			}
			_, port, _ := net.SplitHostPort(addr)
			for _, ip := range FallbackAPIIPs {
				if c2, e2 := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, port)); e2 == nil {
					return c2, nil
				}
			}
			return nil, err
		},
	}
	c.HTTP = &http.Client{Transport: tr, Timeout: 30 * time.Second}
	return c
}

type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("warp api: HTTP %d: %s", e.Status, strings.TrimSpace(e.Body))
}

// do sends a request with the client's identity. If the macOS identity is
// rejected with a 4xx (other than 429), the request is retried once with the
// Android identity so a server-side difference can't break the tunnel.
func (c *Client) do(ctx context.Context, method, path, token string, in, out any) error {
	err := c.doAs(ctx, c.Identity, method, path, token, in, out)
	var ae *APIError
	if c.Identity != AndroidIdentity && errors.As(err, &ae) && ae.Status/100 == 4 && ae.Status != http.StatusTooManyRequests {
		log.Printf("warp api: %s %s rejected with the %s identity (HTTP %d); retrying with the Android identity",
			method, path, c.Identity.UserAgent, ae.Status)
		return c.doAs(ctx, AndroidIdentity, method, path, token, in, out)
	}
	return err
}

// doAs sends one request with the given identity. Responses wrapped in the
// {"result": ..., "success": ..., "errors": [...]} envelope (used by /v0/)
// are unwrapped; a "success": false envelope is returned as an APIError.
func (c *Client) doAs(ctx context.Context, id Identity, method, path, token string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	base := c.BaseURL
	if base == "" {
		base = "https://" + c.Host
	}
	url := fmt.Sprintf("%s/%s/%s", strings.TrimRight(base, "/"), id.Version, strings.TrimPrefix(path, "/"))
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", id.UserAgent)
	req.Header.Set("CF-Client-Version", id.ClientVersion)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode/100 != 2 {
		return &APIError{Status: resp.StatusCode, Body: string(data)}
	}
	data, err = unwrapEnvelope(resp.StatusCode, data)
	if err != nil {
		return err
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// unwrapEnvelope returns the "result" of an API envelope, or data unchanged
// when the response is not an envelope (v0a4471 returns bare objects).
func unwrapEnvelope(status int, data []byte) ([]byte, error) {
	var env struct {
		Result  json.RawMessage `json:"result"`
		Success *bool           `json:"success"`
	}
	if len(data) == 0 || data[0] != '{' || json.Unmarshal(data, &env) != nil || env.Success == nil {
		return data, nil
	}
	if !*env.Success {
		return nil, &APIError{Status: status, Body: string(data)}
	}
	if len(env.Result) == 0 || string(env.Result) == "null" {
		return nil, nil
	}
	return env.Result, nil
}

// Register creates a new anonymous consumer registration bound to a
// WireGuard (curve25519) public key. deviceType and model are what Cloudflare
// lists in the account's device list (the official macOS client sends
// "macOS" and the hw.model string, e.g. "Mac16,8").
func (c *Client) Register(ctx context.Context, wgPublicKey, deviceType, model, locale string) (*Registration, error) {
	in := map[string]any{
		"key":        wgPublicKey,
		"install_id": "",
		"fcm_token":  "",
		"tos":        time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"model":      model,
		"type":       deviceType,
		"locale":     locale,
	}
	// Register with the identity matching the device type, so the engine's
	// Android fallback really registers as Android.
	id := AndroidIdentity
	if deviceType == "macOS" {
		id = MacIdentity
	}
	var raw json.RawMessage
	if err := c.doAs(ctx, id, http.MethodPost, "reg", "", in, &raw); err != nil {
		return nil, err
	}
	reg, err := decodeRegistration(raw)
	if err != nil {
		return nil, err
	}
	if len(reg.Config.Peers) == 0 {
		// Unusable answer: don't leave a stray registration behind.
		c.Delete(ctx, reg.ID, reg.Token)
		return nil, fmt.Errorf("registration response has no peers")
	}
	return reg, nil
}

// decodeRegistration accepts both the bare registration object (v0a4471) and
// the {"result": {...}, "success": true} envelope used by other API versions.
func decodeRegistration(raw json.RawMessage) (*Registration, error) {
	var env struct {
		Result json.RawMessage `json:"result"`
	}
	body := []byte(raw)
	if json.Unmarshal(raw, &env) == nil && len(env.Result) > 0 && env.Result[0] == '{' {
		body = env.Result
	}
	var reg Registration
	if err := json.Unmarshal(body, &reg); err != nil {
		return nil, err
	}
	if reg.ID == "" || reg.Token == "" {
		var top map[string]json.RawMessage
		json.Unmarshal(body, &top)
		keys := make([]string, 0, len(top))
		for k := range top {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return nil, fmt.Errorf("registration response missing id or token (fields: %s)", strings.Join(keys, ", "))
	}
	return &reg, nil
}

func (c *Client) Get(ctx context.Context, id, token string) (*Registration, error) {
	var reg Registration
	if err := c.do(ctx, http.MethodGet, "reg/"+id, token, nil, &reg); err != nil {
		return nil, err
	}
	return &reg, nil
}

// SetKey replaces the tunnel key on the registration. keyType is
// "curve25519" (WireGuard) or "secp256r1" (MASQUE); for MASQUE the key is
// the base64 PKIX DER public key.
func (c *Client) SetKey(ctx context.Context, id, token, key, keyType, tunType string) (*Registration, error) {
	in := map[string]any{"key": key, "key_type": keyType, "tunnel_type": tunType}
	var reg Registration
	if err := c.do(ctx, http.MethodPatch, "reg/"+id, token, in, &reg); err != nil {
		return nil, err
	}
	return &reg, nil
}

func (c *Client) SetName(ctx context.Context, id, token, name string) error {
	return c.do(ctx, http.MethodPatch, "reg/"+id+"/account/reg/"+id, token, map[string]any{"name": name}, nil)
}

func (c *Client) Account(ctx context.Context, id, token string) (*Account, error) {
	var a Account
	if err := c.do(ctx, http.MethodGet, "reg/"+id+"/account", token, nil, &a); err != nil {
		return nil, err
	}
	return &a, nil
}

// SetLicense attaches the registration to another account (WARP+ key).
func (c *Client) SetLicense(ctx context.Context, id, token, license string) (*Account, error) {
	var a Account
	if err := c.do(ctx, http.MethodPut, "reg/"+id+"/account", token, map[string]any{"license": license}, &a); err != nil {
		return nil, err
	}
	return &a, nil
}

func (c *Client) Devices(ctx context.Context, id, token string) ([]Device, error) {
	var d []Device
	if err := c.do(ctx, http.MethodGet, "reg/"+id+"/account/devices", token, nil, &d); err != nil {
		return nil, err
	}
	return d, nil
}

func (c *Client) Delete(ctx context.Context, id, token string) error {
	return c.do(ctx, http.MethodDelete, "reg/"+id, token, nil, nil)
}
