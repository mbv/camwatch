package mtp

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/pion/stun/v3"
)

// default STUN servers — fallback only when LoginResponse has no MA_STUN_ADDRS.
var mediaSTUNServers = []string{
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
}

// parseStunAddrList unpacks MA_STUN_ADDRS (0x002d):
//
//	u32be count | count × 20 B MSIP (family 0x0202, port be, IPv4)
//
// Native Frida: these are Azure hosts on :443 (e.g. 20.157.97.83:443), probed
// via classic STUN Binding before MediaBinding / CNT|.
func parseStunAddrList(blob []byte) []string {
	if len(blob) < 4 {
		return nil
	}
	count := int(binary.BigEndian.Uint32(blob[:4]))
	off := 4
	var out []string
	for i := 0; i < count && off+20 <= len(blob); i++ {
		if host := msipHostPort(blob[off : off+20]); host != "" {
			out = append(out, host)
		}
		off += 20
	}
	if len(out) > 0 {
		return out
	}
	// Fallback: scan for 0x0202 attrs (older/unknown layouts).
	for i := 0; i+20 <= len(blob); i++ {
		if host := msipHostPort(blob[i : i+20]); host != "" {
			out = append(out, host)
			i += 19
		}
	}
	return out
}

func msipHostPort(a []byte) string {
	if len(a) < 8 || a[0] != 0x02 || a[1] != 0x02 {
		return ""
	}
	port := binary.BigEndian.Uint16(a[2:4])
	ip := net.IP(a[4:8]).To4()
	if ip == nil || isZero(ip) || port == 0 {
		return ""
	}
	return net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
}

// discoverBuddyAddr STUN-binds on conn and returns a 20 B MSIP 0x0015 attr.
// Probes LoginResponse MA_STUN_ADDRS in parallel (native NAT_StartProbe), then
// falls back to public STUN if needed.
func discoverBuddyAddr(conn *net.UDPConn, extraServers ...string) ([]byte, error) {
	primary := dedupeServers(extraServers)
	fallback := mediaSTUNServers
	if len(primary) == 0 {
		primary = fallback
		fallback = nil
	}

	buddy, last := probeSTUNServersParallel(conn, primary)
	if buddy != nil {
		return buddy, nil
	}
	buddy, err := probeSTUNServersParallel(conn, fallback)
	if buddy != nil {
		return buddy, nil
	}
	if err != nil {
		last = err
	}
	if last == nil {
		last = fmt.Errorf("stun: no servers")
	}
	return nil, last
}

func dedupeServers(servers []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range servers {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// probeSTUNServersParallel sends Binding Requests to all servers, then reads
// until the first XOR-MAPPED success or deadline. Remaining servers still get
// a request (native probes the full MA_STUN_ADDRS list).
func probeSTUNServersParallel(conn *net.UDPConn, servers []string) ([]byte, error) {
	if len(servers) == 0 {
		return nil, nil
	}
	type tx struct {
		addr *net.UDPAddr
		id   [stun.TransactionIDSize]byte
	}
	var txs []tx
	for _, server := range servers {
		addr, err := net.ResolveUDPAddr("udp", server)
		if err != nil {
			Logf("mtp: STUN resolve %s: %v\n", server, err)
			continue
		}
		msg, err := stun.Build(stun.TransactionID, stun.BindingRequest)
		if err != nil {
			continue
		}
		var id [stun.TransactionIDSize]byte
		copy(id[:], msg.TransactionID[:])
		if _, err = conn.WriteToUDP(msg.Raw, addr); err != nil {
			Logf("mtp: STUN write %s: %v\n", server, err)
			continue
		}
		txs = append(txs, tx{addr: addr, id: id})
		Logf("mtp: STUN TX %s\n", server)
	}
	if len(txs) == 0 {
		return nil, fmt.Errorf("stun: no servers reachable")
	}

	deadline := time.Now().Add(2 * time.Second)
	_ = conn.SetReadDeadline(deadline)
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	buf := make([]byte, 1500)
	var last error
	ok := 0
	var buddy []byte
	for time.Now().Before(deadline) {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			last = err
			break
		}
		var res stun.Message
		if err = stun.Decode(buf[:n], &res); err != nil {
			continue
		}
		if res.Type != stun.BindingSuccess {
			continue
		}
		var xor stun.XORMappedAddress
		if err = xor.GetFrom(&res); err != nil {
			continue
		}
		ip4 := xor.IP.To4()
		if ip4 == nil {
			continue
		}
		out := make([]byte, 20)
		out[0], out[1] = 0x02, 0x02
		binary.BigEndian.PutUint16(out[2:4], uint16(xor.Port))
		copy(out[4:8], ip4)
		ok++
		Logf("mtp: STUN %v → %v:%d\n", from, ip4, xor.Port)
		if buddy == nil {
			buddy = out
			// Keep reading briefly for more probes; don't wait full deadline.
			deadline = time.Now().Add(300 * time.Millisecond)
			_ = conn.SetReadDeadline(deadline)
		}
	}
	if buddy != nil {
		Logp("mtp: STUN probed ok=%d sent=%d\n", ok, len(txs))
		return buddy, nil
	}
	if last == nil {
		last = fmt.Errorf("stun: no XOR-mapped response")
	}
	return nil, last
}
