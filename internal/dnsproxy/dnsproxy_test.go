package dnsproxy

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

// query builds a minimal A query for name.
func query(id uint16, name string) []byte {
	q := []byte{byte(id >> 8), byte(id), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range splitDots(name) {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	return append(q, 0, 0, 1, 0, 1)
}

func splitDots(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return out
}

func TestQName(t *testing.T) {
	if got := QName(query(1, "Printer.LAN")); got != "printer.lan" {
		t.Fatal(got)
	}
}

// Local Domain Fallback: suffix matches go to the local resolver.
func TestFallbackDomainsUseLocalResolver(t *testing.T) {
	local, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	defer local.Close()
	go func() {
		b := make([]byte, 512)
		n, a, err := local.ReadFromUDP(b)
		if err == nil {
			b[2] |= 0x80 // mark as response
			local.WriteToUDP(b[:n], a)
		}
	}()
	port := local.LocalAddr().(*net.UDPAddr).Port
	s := &Server{FallbackDomains: []string{"lan"}, Upstream: UDP, Resolver: Families("off")}
	// Point fallback at our fake resolver on a non-53 port via udpExchange directly.
	if !s.isFallback("printer.lan") || s.isFallback("example.com") || s.isFallback("plan") {
		t.Fatal("suffix matching wrong")
	}
	r, err := udpExchange(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)), query(7, "printer.lan"))
	if err != nil || r[2]&0x80 == 0 {
		t.Fatalf("exchange: %v", err)
	}
	_ = time.Second
}

func TestFamilies(t *testing.T) {
	if Families("full").IPs[0].String() != "1.1.1.3" || Families("malware").DoHHost != "security.cloudflare-dns.com" || Families("off").IPs[0].String() != "1.1.1.1" {
		t.Fatal("families mapping")
	}
}
