// SPDX-License-Identifier: MIT
//
// CSQTT TUN is IPv4-only. Android 16 / Chrome still send IPv6 literals through
// SOCKS (Happy Eyeballs). Map them to IPv4: 4in6, NAT64 64:ff9b::/96, 6to4, or
// PTR then A via the same protected DNS the helper already uses.

package main

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var ipv4Mapped sync.Map // netip.Addr → netip.Addr (v4)

func mapIPv6To4(ip netip.Addr, resolver *protectedResolver) (netip.Addr, error) {
	ip = ip.Unmap()
	if ip.Is4() {
		return ip, nil
	}
	if !ip.Is6() {
		return netip.Addr{}, fmt.Errorf("not an IP")
	}
	if v, ok := ipv4Mapped.Load(ip); ok {
		return v.(netip.Addr), nil
	}
	v4, err := deriveIPv4(ip, resolver)
	if err != nil {
		return netip.Addr{}, err
	}
	ipv4Mapped.Store(ip, v4)
	log.Printf("[SOCKS] IPv6 %s → IPv4 %s", ip, v4)
	return v4, nil
}

func deriveIPv4(ip netip.Addr, resolver *protectedResolver) (netip.Addr, error) {
	if v4, ok := nat64Embedded(ip); ok {
		return v4, nil
	}
	if v4, ok := sixToFour(ip); ok {
		return v4, nil
	}
	if v4, ok := cloudflareEmbedded(ip); ok {
		return v4, nil
	}
	name, err := lookupPTRName(resolver, ip)
	if err != nil || name == "" {
		return netip.Addr{}, fmt.Errorf("IPv6 target %v: tunnel is IPv4-only", ip)
	}
	ips, err := resolver.LookupHost(strings.TrimSuffix(name, "."))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("IPv6 target %v: no IPv4 via PTR %s: %w", ip, name, err)
	}
	for _, s := range ips {
		if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("IPv6 target %v: PTR %s has no A record", ip, name)
}

func nat64Embedded(ip netip.Addr) (netip.Addr, bool) {
	b := ip.As16()
	// RFC 6052 well-known prefix 64:ff9b::/96
	if b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b &&
		b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0 &&
		b[8] == 0 && b[9] == 0 && b[10] == 0 && b[11] == 0 {
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	}
	return netip.Addr{}, false
}

func sixToFour(ip netip.Addr) (netip.Addr, bool) {
	b := ip.As16()
	if b[0] == 0x20 && b[1] == 0x02 {
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	}
	return netip.Addr{}, false
}

// Cloudflare 2606:4700::/32 stores the matching IPv4 in the last 32 bits.
func cloudflareEmbedded(ip netip.Addr) (netip.Addr, bool) {
	b := ip.As16()
	if b[0] == 0x26 && b[1] == 0x06 && b[2] == 0x47 && b[3] == 0x00 {
		v4 := netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
		if v4.IsGlobalUnicast() && !v4.IsPrivate() {
			return v4, true
		}
	}
	return netip.Addr{}, false
}

func lookupPTRName(resolver *protectedResolver, ip netip.Addr) (string, error) {
	if resolver == nil {
		return "", fmt.Errorf("no resolver")
	}
	servers := resolver.servers
	if len(servers) == 0 {
		servers = []string{"77.88.8.8:53", "77.88.8.1:53"}
	}
	qname := ptrName(ip)
	var last error
	for _, srv := range servers {
		name, err := queryPTR(srv, resolver.protectPath, qname)
		if err == nil && name != "" {
			return name, nil
		}
		last = err
	}
	if last == nil {
		last = fmt.Errorf("dns: no PTR for %s", ip)
	}
	return "", last
}

func ptrName(ip netip.Addr) string {
	if ip.Is4() {
		b := ip.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", b[3], b[2], b[1], b[0])
	}
	b := ip.As16()
	var s strings.Builder
	s.Grow(72)
	for i := len(b) - 1; i >= 0; i-- {
		fmt.Fprintf(&s, "%x.%x.", b[i]&0xf, b[i]>>4)
	}
	s.WriteString("ip6.arpa.")
	return s.String()
}

func queryPTR(server, protectPath, fqdn string) (string, error) {
	name, err := dnsmessage.NewName(fqdn)
	if err != nil {
		return "", err
	}
	d := net.Dialer{Timeout: 2 * time.Second, Control: dialControl(protectPath, nil)}
	conn, err := d.Dial("udp", server)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	id := uint16(time.Now().UnixNano())
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}},
	}
	packed, err := msg.Pack()
	if err != nil {
		return "", err
	}
	if _, err := conn.Write(packed); err != nil {
		return "", err
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	var resp dnsmessage.Message
	if err := resp.Unpack(buf[:n]); err != nil {
		return "", err
	}
	if resp.Header.ID != id || resp.Header.RCode != dnsmessage.RCodeSuccess {
		return "", fmt.Errorf("ptr rcode=%v", resp.Header.RCode)
	}
	for _, a := range resp.Answers {
		if rr, ok := a.Body.(*dnsmessage.PTRResource); ok {
			return strings.TrimSuffix(rr.PTR.String(), "."), nil
		}
	}
	return "", fmt.Errorf("no PTR answer")
}

func onlyIPv4(ips []string) []string {
	var out []string
	for _, s := range ips {
		if a := net.ParseIP(s); a != nil && a.To4() != nil {
			out = append(out, a.To4().String())
		}
	}
	return out
}
