package mesh

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestParseUAPI(t *testing.T) {
	pkRaw := bytes.Repeat([]byte{0x11}, 32)
	dump := "private_key=00\n" +
		"listen_port=0\n" +
		"public_key=" + hex.EncodeToString(pkRaw) + "\n" +
		"endpoint=[fd00::1]:0\n" +
		"last_handshake_time_sec=1700000000\n" +
		"last_handshake_time_nsec=5\n" +
		"rx_bytes=328\n" +
		"tx_bytes=364\n" +
		"persistent_keepalive_interval=25\n" +
		"allowed_ip=100.64.0.1/32\n" +
		"errno=0\n"

	peers := parseUAPI(dump)
	if len(peers) != 1 {
		t.Fatalf("peers = %d, want 1", len(peers))
	}
	p := peers[0]
	if want := base64.StdEncoding.EncodeToString(pkRaw); p.PublicKey != want {
		t.Fatalf("public key = %q, want base64 %q", p.PublicKey, want)
	}
	if p.LastHandshakeSec != 1700000000 {
		t.Fatalf("handshake = %d", p.LastHandshakeSec)
	}
	if p.RxBytes != 328 || p.TxBytes != 364 {
		t.Fatalf("rx/tx = %d/%d, want 328/364", p.RxBytes, p.TxBytes)
	}
	if len(p.AllowedIPs) != 1 || p.AllowedIPs[0] != "100.64.0.1/32" {
		t.Fatalf("allowed = %v", p.AllowedIPs)
	}
}

func TestParseUAPIEmptyOrNoPeers(t *testing.T) {
	if got := parseUAPI(""); got != nil {
		t.Fatalf("empty dump -> %v, want nil", got)
	}
	if got := parseUAPI("private_key=00\nlisten_port=0\nerrno=0\n"); got != nil {
		t.Fatalf("no-peer dump -> %v, want nil", got)
	}
}

func TestSortPeersByOverlay(t *testing.T) {
	// Overlay IPs out of order; peer "b" carries a subnet route BEFORE its overlay
	// /32 (the sort must key on the overlay, not the first allowed-ip); "z" has no
	// overlay (sorts last);.10 must land AFTER.5 (numeric, not lexicographic).
	peers := []PeerStatus{
		{PublicKey: "e", AllowedIPs: []string{"100.64.0.10/32"}},
		{PublicKey: "b", AllowedIPs: []string{"192.168.9.0/24", "100.64.0.4/32"}},
		{PublicKey: "z", AllowedIPs: []string{"10.0.0.0/8"}},
		{PublicKey: "c", AllowedIPs: []string{"100.64.0.5/32"}},
	}
	const want = "b,c,e,z" // 100.64.0.4,.5,.10 (numeric), then the overlay-less peer
	join := func() string {
		s := ""
		for i, p := range peers {
			if i > 0 {
				s += ","
			}
			s += p.PublicKey
		}
		return s
	}
	sortPeersByOverlay(peers)
	if got := join(); got != want {
		t.Fatalf("order = %s, want %s", got, want)
	}
	sortPeersByOverlay(peers) // stable + idempotent: a second pass must not reshuffle
	if got := join(); got != want {
		t.Fatalf("re-sort changed order = %s, want %s", got, want)
	}
}
