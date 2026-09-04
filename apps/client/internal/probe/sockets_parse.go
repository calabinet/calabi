package probe

// Pure parsers for the two text socket tables (Linux /proc/net/tcp{,6} and BSD
// netstat). Kept free of build tags and of any I/O so they can be unit-tested on
// every platform — the tagged files (sockets_linux.go, sockets_darwin.go) only
// read the bytes and hand them here.

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"net/netip"
	"strconv"
	"strings"
)

// tcpStateListen is TCP_LISTEN in /proc/net/tcp's hex "st" column.
const tcpStateListen = 0x0A

// parseProcNetTCP parses a /proc/net/tcp (v6=false) or /proc/net/tcp6 (v6=true)
// dump and returns its LISTENing sockets. The address column is a packed hex
// form in the kernel's own (little-endian, per-32-bit-word) byte order;
// parseHexAddr.
func parseProcNetTCP(data []byte, v6 bool) ([]listener, error) {
	var out []listener
	sc := bufio.NewScanner(bytes.NewReader(data))
	header := true
	for sc.Scan() {
		if header { // "  sl  local_address rem_address   st ..."
			header = false
			continue
		}
		f := strings.Fields(sc.Text())
		// f[1] = local_address, f[3] = connection state (hex).
		if len(f) < 4 {
			continue
		}
		st, err := strconv.ParseUint(f[3], 16, 16)
		if err != nil || st != tcpStateListen {
			continue
		}
		ip, port, ok := parseHexAddr(f[1], v6)
		if !ok {
			continue
		}
		out = append(out, listener{ip: ip, port: port})
	}
	return out, sc.Err()
}

// parseHexAddr decodes a "HEXADDR:HEXPORT" cell from /proc/net/tcp{,6}.
//
// The kernel prints the address as the raw in-memory bytes, which are
// little-endian within each 32-bit word: an IPv4 "0100007F" is the four bytes
// 01 00 00 7F, i.e. 127.0.0.1 read back-to-front, and an IPv6 address is four
// such words each needing its bytes reversed. The port, by contrast, is a plain
// big-endian hex.
func parseHexAddr(cell string, v6 bool) (netip.Addr, int, bool) {
	i := strings.LastIndexByte(cell, ':')
	if i < 0 {
		return netip.Addr{}, 0, false
	}
	hexIP, hexPort := cell[:i], cell[i+1:]
	port, err := strconv.ParseUint(hexPort, 16, 32)
	if err != nil {
		return netip.Addr{}, 0, false
	}

	if v6 {
		if len(hexIP) != 32 {
			return netip.Addr{}, 0, false
		}
		raw, err := hex.DecodeString(hexIP)
		if err != nil {
			return netip.Addr{}, 0, false
		}
		var b [16]byte
		copy(b[:], raw)
		for g := 0; g < 4; g++ { // reverse each 32-bit word
			b[g*4], b[g*4+3] = b[g*4+3], b[g*4]
			b[g*4+1], b[g*4+2] = b[g*4+2], b[g*4+1]
		}
		return netip.AddrFrom16(b), int(port), true
	}

	if len(hexIP) != 8 {
		return netip.Addr{}, 0, false
	}
	raw, err := hex.DecodeString(hexIP)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	return netip.AddrFrom4([4]byte{raw[3], raw[2], raw[1], raw[0]}), int(port), true
}

// parseNetstat parses `netstat -an -p tcp` output (macOS/BSD) and returns its
// LISTENing sockets. Lines look like:
//
//	tcp4  0  0  127.0.0.1.5432  *.*  LISTEN
//	tcp6  0  0  ::1.5432        *.*  LISTEN
//	tcp4  0  0  *.8080          *.*  LISTEN
func parseNetstat(data []byte) ([]listener, error) {
	var out []listener
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 6 || !strings.HasPrefix(f[0], "tcp") || f[len(f)-1] != "LISTEN" {
			continue
		}
		ip, port, ok := parseBSDAddr(f[3], strings.HasPrefix(f[0], "tcp6"))
		if !ok {
			continue
		}
		out = append(out, listener{ip: ip, port: port})
	}
	return out, sc.Err()
}

// parseBSDAddr decodes netstat's "ADDR.PORT" local-address form, where ADDR is
// an IP, or "*" for a wildcard bind, and may carry a "%zone" suffix on IPv6.
func parseBSDAddr(cell string, v6 bool) (netip.Addr, int, bool) {
	dot := strings.LastIndexByte(cell, '.')
	if dot < 0 {
		return netip.Addr{}, 0, false
	}
	host, portStr := cell[:dot], cell[dot+1:]
	if portStr == "*" { // no concrete port; nothing to declare
		return netip.Addr{}, 0, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	if z := strings.IndexByte(host, '%'); z >= 0 {
		host = host[:z]
	}
	if host == "*" {
		if v6 {
			return netip.IPv6Unspecified(), port, true
		}
		return netip.IPv4Unspecified(), port, true
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	return ip, port, true
}
