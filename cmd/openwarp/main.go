// Command openwarp is a Cloudflare WARP-compatible client: a daemon plus a CLI
// modelled on warp-cli.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ImanMontajabi/OpenWarp/internal/buildinfo"
	"github.com/ImanMontajabi/OpenWarp/internal/daemon"
	"github.com/ImanMontajabi/OpenWarp/internal/state"
)

var jsonOut bool

const usage = `openwarp - Cloudflare WARP compatible client

Usage: openwarp [-j] <command> [args]

Service:
  daemon [--state DIR] [--socket PATH]  Run the service (root for tun modes)
  service install|uninstall|status      Install/remove the LaunchDaemon (sudo), or check it

Connection:
  status [-l]                           Connection status (-l: keep watching)
  connect | disconnect
  mode <warp|warp+doh|warp+dot|doh|dot|proxy|tunnel_only>
  stats                                 Tunnel / DNS statistics

Leak protection:
  killswitch on|off|status              Block traffic outside the tunnel (experimental; pf, needs the service)
  verify [--cloudflare]                 Check routes, DNS and the kill switch (--cloudflare: also ask
                                        Cloudflare whether this request arrives through WARP)
  recover                               (sudo) Remove the kill switch rules and undo routes/DNS left
                                        by a crashed daemon; works without the daemon

Registration:
  registration new [--accept-tos]       Register this device with Cloudflare
  registration show | delete | devices | account
  registration license <KEY>            Attach to a WARP+ license key

Tunnel:
  tunnel protocol set <masque|wireguard> | reset
  tunnel endpoint set <IP:PORT> | reset
  tunnel ip add|remove <CIDR> | list | reset     Split-tunnel IPs
  tunnel split-mode <exclude|include>
  tunnel mtu <N>
  tunnel pq <on|off>                    Post-quantum key exchange for MASQUE
  tunnel rotate-keys

DNS / proxy / trusted networks:
  dns families <off|malware|full>
  dns fallback add|remove <DOMAIN> | list | reset
  proxy port <PORT>
  trusted ssid add|remove <SSID> | list
  trusted wifi|ethernet enable|disable

Settings:
  settings [list] | reset
`

func main() {
	args := os.Args[1:]
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "-j", "--json":
			jsonOut = true
		case "-V", "--version":
			fmt.Println("openwarp", buildinfo.Full())
			return
		case "-h", "--help":
			fmt.Print(usage)
			return
		default:
			die("unknown flag %s", args[0])
		}
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Print(usage)
		os.Exit(2)
	}
	if err := run(args); err != nil {
		die("%v", err)
	}
}

func die(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "Error: "+f+"\n", a...)
	os.Exit(1)
}

// ---------- control client ----------

func client() *http.Client {
	sock := daemon.SocketPath()
	return &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		}},
	}
}

func call(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, "http://openwarp"+path, body)
	resp, err := client().Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach the openwarp daemon at %s (start it with `sudo openwarp daemon` or `openwarp service install`): %v", daemon.SocketPath(), err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		var e struct{ Error string }
		json.Unmarshal(data, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(data))
		}
		return errors.New(e.Error)
	}
	if jsonOut && out == nil {
		os.Stdout.Write(data)
		return nil
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	fmt.Println("Success")
	return nil
}

func printJSON(v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

func patch(m map[string]any) error {
	var s state.Settings
	if err := call("PATCH", "/v1/settings", m, &s); err != nil {
		return err
	}
	if jsonOut {
		printJSON(s)
	} else {
		fmt.Println("Success")
	}
	return nil
}

func settings() state.Settings {
	var s state.Settings
	if err := call("GET", "/v1/settings", nil, &s); err != nil {
		die("%v", err)
	}
	return s
}

func need(args []string, n int, what string) {
	if len(args) < n {
		die("missing argument: %s", what)
	}
}

// ---------- commands ----------

func run(args []string) error {
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "daemon":
		return runDaemon(rest)
	case "service":
		need(rest, 1, "install|uninstall|status")
		return service(rest[0])
	case "status":
		return status(slices.Contains(rest, "-l") || slices.Contains(rest, "--listen"))
	case "connect":
		return call("POST", "/v1/connect", nil, nil)
	case "disconnect":
		return call("POST", "/v1/disconnect", nil, nil)
	case "mode":
		need(rest, 1, "mode")
		if !state.Mode(rest[0]).Valid() {
			return fmt.Errorf("invalid mode %q; one of %v", rest[0], state.AllModes)
		}
		return patch(map[string]any{"mode": rest[0]})
	case "stats":
		return stats()
	case "killswitch":
		return killSwitchCmd(rest)
	case "verify":
		return verifyCmd(slices.Contains(rest, "--cloudflare"))
	case "recover":
		return recoverCmd()
	case "registration":
		return registration(rest)
	case "tunnel":
		return tunnelCmd(rest)
	case "dns":
		return dnsCmd(rest)
	case "proxy":
		need(rest, 2, "port <PORT>")
		p, err := strconv.Atoi(rest[1])
		if rest[0] != "port" || err != nil || p < 1 || p > 65535 {
			return errors.New("usage: openwarp proxy port <1-65535>")
		}
		return patch(map[string]any{"proxy_port": p})
	case "trusted":
		return trusted(rest)
	case "settings":
		if len(rest) > 0 && rest[0] == "reset" {
			return call("POST", "/v1/settings/reset", nil, nil)
		}
		return listSettings()
	case "help":
		fmt.Print(usage)
		return nil
	}
	return fmt.Errorf("unknown command %q (see `openwarp help`)", cmd)
}

func runDaemon(args []string) error {
	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	dir := fs.String("state", state.DefaultDir(), "state directory")
	sock := fs.String("socket", daemon.SocketPath(), "control socket path")
	fs.Parse(args)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	store, err := state.Open(*dir)
	if err != nil {
		return err
	}
	eng := daemon.NewEngine(store)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("openwarp daemon %s (state %s, euid %d)", buildinfo.Full(), *dir, os.Geteuid())
	err = eng.Serve(ctx, *sock)
	eng.Shutdown()
	return err
}

func human(n uint64) string {
	f := float64(n)
	for _, u := range []string{"B", "KB", "MB", "GB", "TB"} {
		if f < 1024 {
			return fmt.Sprintf("%.1f %s", f, u)
		}
		f /= 1024
	}
	return fmt.Sprintf("%.1f PB", f)
}

func status(listen bool) error {
	last := ""
	for {
		var st daemon.Status
		if err := call("GET", "/v1/status", nil, &st); err != nil {
			return err
		}
		if jsonOut {
			printJSON(st)
		} else {
			line := "Status update: " + st.Status
			if st.Reason != "" {
				line += "\nReason: " + st.Reason
			}
			if st.Error != "" {
				line += "\nLast error: " + st.Error
			}
			if !st.Registered {
				line += "\nNot registered. Run `openwarp registration new --accept-tos`."
			}
			if st.Status == daemon.StatusConnected {
				line += fmt.Sprintf("\nMode: %s (%s)", st.ModeLabel, st.Mode)
				if st.Tunnel != nil {
					line += fmt.Sprintf("\nTunnel: %s via %s", st.Tunnel.Protocol, st.Tunnel.Endpoint)
				}
				if st.Proxy != "" {
					line += "\nProxy: socks5/http://" + st.Proxy
				}
			}
			line += "\n" + protectionText(st.Protection)
			if line != last {
				fmt.Println(line)
				last = line
			}
		}
		if !listen {
			return nil
		}
		time.Sleep(time.Second)
	}
}

func stats() error {
	var st daemon.Status
	if err := call("GET", "/v1/status", nil, &st); err != nil {
		return err
	}
	if jsonOut {
		printJSON(map[string]any{"tunnel": st.Tunnel, "dns": st.DNS})
		return nil
	}
	if st.Tunnel == nil && st.DNS == nil {
		fmt.Println("Not connected")
		return nil
	}
	if t := st.Tunnel; t != nil {
		fmt.Printf("Tunnel protocol:   %s\nEndpoint:          %s\nSent:              %s\nReceived:          %s\n",
			t.Protocol, t.Endpoint, human(t.TxBytes), human(t.RxBytes))
		if !t.LastHandshake.IsZero() {
			fmt.Printf("Last handshake:    %s ago\n", time.Since(t.LastHandshake).Round(time.Second))
		}
		if t.HandshakeRTT != "" {
			fmt.Printf("Handshake time:    %s\n", t.HandshakeRTT)
		}
		if t.TLS != "" {
			fmt.Printf("TLS:               %s\n", t.TLS)
		}
		fmt.Printf("Interface:         %s %s %s\n", st.Interface, st.InterfaceV4, st.InterfaceV6)
	}
	if d := st.DNS; d != nil {
		fmt.Printf("DNS queries:       %d (fallback %d, failed %d)\n", d.Queries, d.Fallback, d.Failures)
	}
	return nil
}

func registration(args []string) error {
	need(args, 1, "new|show|delete|devices|account|license")
	switch args[0] {
	case "new":
		accept := slices.Contains(args, "--accept-tos")
		if !accept {
			fmt.Print("Cloudflare WARP Terms of Service: https://www.cloudflare.com/application/terms/\nAccept? [y/N] ")
			var a string
			fmt.Scanln(&a)
			accept = strings.HasPrefix(strings.ToLower(a), "y")
		}
		var v daemon.RegistrationView
		if err := call("POST", "/v1/registration", map[string]bool{"accept_tos": accept}, &v); err != nil {
			return err
		}
		if jsonOut {
			printJSON(v)
		} else {
			fmt.Println("Success")
		}
		return nil
	case "show":
		var v daemon.RegistrationView
		if err := call("GET", "/v1/registration", nil, &v); err != nil {
			return err
		}
		if jsonOut {
			printJSON(v)
			return nil
		}
		fmt.Printf("Account type: %s\nID: %s\nAccount ID: %s\nLicense: %s\nWARP+: %v\nKey type: %s\nPublic key: %s\nInterface: %s, %s\n",
			v.AccountType, v.ID, v.AccountID, v.License, v.WarpPlus, v.KeyType, v.PublicKey, v.InterfaceV4, v.InterfaceV6)
		if v.Peer != nil {
			fmt.Printf("Edge: v4=%s v6=%s\n", v.Peer.Endpoint.V4, v.Peer.Endpoint.V6)
		}
		return nil
	case "delete":
		return call("DELETE", "/v1/registration", nil, nil)
	case "account":
		return call("GET", "/v1/registration/account", nil, nil)
	case "devices":
		var d []map[string]any
		if err := call("GET", "/v1/registration/devices", nil, &d); err != nil {
			return err
		}
		if jsonOut {
			printJSON(d)
			return nil
		}
		for _, x := range d {
			fmt.Printf("%-10v %-28v active=%v  %v\n", x["type"], x["model"], x["active"], x["name"])
		}
		return nil
	case "license":
		need(args, 2, "license key")
		return call("PUT", "/v1/registration/license", map[string]string{"license": args[1]}, nil)
	}
	return fmt.Errorf("unknown registration command %q", args[0])
}

func listEdit(key string, cur []string, args []string, def []string) error {
	need(args, 1, "add|remove|list|reset")
	switch args[0] {
	case "list":
		for _, x := range cur {
			fmt.Println(x)
		}
		return nil
	case "reset":
		return patch(map[string]any{key: def})
	case "add":
		need(args, 2, "value")
		if !slices.Contains(cur, args[1]) {
			cur = append(cur, args[1])
		}
		return patch(map[string]any{key: cur})
	case "remove":
		need(args, 2, "value")
		return patch(map[string]any{key: slices.DeleteFunc(cur, func(s string) bool { return s == args[1] })})
	}
	return fmt.Errorf("unknown action %q", args[0])
}

func tunnelCmd(args []string) error {
	need(args, 1, "subcommand")
	switch args[0] {
	case "protocol":
		need(args, 2, "set|reset")
		if args[1] == "reset" {
			return patch(map[string]any{"protocol": state.ProtoMasque})
		}
		need(args, 3, "masque|wireguard")
		return patch(map[string]any{"protocol": strings.ToLower(args[2])})
	case "endpoint":
		need(args, 2, "set|reset")
		if args[1] == "reset" {
			return patch(map[string]any{"endpoint_override": ""})
		}
		need(args, 3, "IP:PORT")
		return patch(map[string]any{"endpoint_override": args[2]})
	case "ip":
		s := settings()
		def := state.DefaultExcludes
		if s.SplitMode == state.SplitInclude {
			def = []string{}
		}
		return listEdit("split_ips", s.SplitIPs, args[1:], def)
	case "split-mode":
		need(args, 2, "exclude|include")
		m := map[string]any{"split_mode": args[1]}
		if args[1] == "include" {
			m["split_ips"] = []string{}
		} else if args[1] == "exclude" {
			m["split_ips"] = state.DefaultExcludes
		} else {
			return errors.New("split-mode must be exclude or include")
		}
		return patch(m)
	case "mtu":
		need(args, 2, "N")
		n, err := strconv.Atoi(args[1])
		if err != nil || n < 1280 || n > 1500 {
			return errors.New("mtu must be 1280-1500")
		}
		return patch(map[string]any{"mtu": n})
	case "pq":
		need(args, 2, "on|off")
		return patch(map[string]any{"post_quantum": args[1] == "on"})
	case "rotate-keys":
		return call("POST", "/v1/tunnel/rotate-keys", nil, nil)
	case "stats":
		return stats()
	}
	return fmt.Errorf("unknown tunnel command %q", args[0])
}

func dnsCmd(args []string) error {
	need(args, 1, "families|fallback")
	switch args[0] {
	case "families":
		need(args, 2, "off|malware|full")
		if !slices.Contains([]string{"off", "malware", "full"}, args[1]) {
			return errors.New("families must be off, malware or full")
		}
		return patch(map[string]any{"families": args[1]})
	case "fallback":
		return listEdit("fallback_domains", settings().FallbackDomains, args[1:], state.DefaultFallbackDomains)
	}
	return fmt.Errorf("unknown dns command %q", args[0])
}

func trusted(args []string) error {
	need(args, 2, "ssid|wifi|ethernet ...")
	switch args[0] {
	case "ssid":
		return listEdit("trusted_ssids", settings().TrustedSSIDs, args[1:], []string{})
	case "wifi":
		return patch(map[string]any{"disable_wifi": args[1] == "enable"})
	case "ethernet":
		return patch(map[string]any{"disable_ethernet": args[1] == "enable"})
	}
	return fmt.Errorf("unknown trusted command %q", args[0])
}

func listSettings() error {
	s := settings()
	if jsonOut {
		printJSON(s)
		return nil
	}
	fmt.Printf("Mode: %s (%s)\nTunnel protocol: %s\nPost-quantum (MASQUE): %v\nAlways on: %v\n1.1.1.1 for Families: %s\nProxy port: %d\nMTU: %d\n",
		s.Mode.Label(), s.Mode, s.Protocol, s.PostQuantum, s.AlwaysOn, s.Families, s.ProxyPort, s.MTU)
	if s.EndpointOverride != "" {
		fmt.Printf("Endpoint override: %s\n", s.EndpointOverride)
	}
	fmt.Printf("Disabled for Wi-Fi: %v\nDisabled for Ethernet: %v\nTrusted SSIDs: %v\n", s.DisableWiFi, s.DisableEthernet, s.TrustedSSIDs)
	fmt.Printf("Split tunnel (%s mode):\n", s.SplitMode)
	for _, x := range s.SplitIPs {
		fmt.Println("  " + x)
	}
	fmt.Println("Fallback domains:")
	for _, x := range s.FallbackDomains {
		fmt.Println("  " + x)
	}
	return nil
}

// ---------- leak protection ----------

func protectionText(p daemon.Protection) string {
	ks := p.KillSwitch
	if p.KillSwitchDetail != "" {
		ks += " (" + p.KillSwitchDetail + ")"
	}
	out := "Protection: " + p.State + "\nKill switch: " + ks
	if p.IPv6 != "" {
		out += "\nIPv6: " + p.IPv6
	}
	if p.DNS != "" {
		out += "\nDNS: " + p.DNS
	}
	return out
}

func killSwitchCmd(args []string) error {
	need(args, 1, "on|off|status")
	switch args[0] {
	case "on", "off":
		return patch(map[string]any{"kill_switch": args[0] == "on"})
	case "status":
		var st daemon.Status
		if err := call("GET", "/v1/status", nil, &st); err != nil {
			return err
		}
		if jsonOut {
			printJSON(st.Protection)
			return nil
		}
		fmt.Println(protectionText(st.Protection))
		return nil
	}
	return fmt.Errorf("unknown killswitch command %q (on, off or status)", args[0])
}

func verifyCmd(cloudflare bool) error {
	path := "/v1/verify"
	if cloudflare {
		path += "?cloudflare=1"
	}
	var v daemon.Verification
	if err := call("POST", path, nil, &v); err != nil {
		return err
	}
	if jsonOut {
		printJSON(v)
		return nil
	}
	for _, c := range v.Checks {
		fmt.Printf("%-5s %-12s %s\n", strings.ToUpper(c.Status), c.Name, c.Detail)
	}
	fmt.Println("Result:", v.Result)
	if v.Result == "incomplete" && !cloudflare {
		fmt.Println("Nothing failed, but nothing proved the tunnel either: run `openwarp verify --cloudflare`.")
	}
	if v.Result == "failed" {
		return errors.New("verification failed")
	}
	return nil
}

// recoverCmd is the way out when the kill switch blocks everything and the daemon is gone or stuck.
func recoverCmd() error {
	if os.Geteuid() != 0 {
		return errors.New("run with sudo")
	}
	for _, msg := range daemon.ResetNetwork(state.DefaultDir()) {
		fmt.Println(msg)
	}
	return nil
}
