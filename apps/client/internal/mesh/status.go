package mesh

import (
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
)

// Status is a point-in-time view of the mesh datapath, for `calabi mesh status`
// and the :7400 console. Built by WGDatapath.Snapshot from the node's overlay +
// the WireGuard device's UAPI dump.
type Status struct {
	Overlay string // this node's overlay IP (e.g. "100.64.0.2"); "" until assigned
	// Relay is the address of the relay this node currently homes at — where peers
	// reach it. With a relay fleet (MESH.4 B2b) this can differ from the relay the
	// node was configured with: the node re-homes onto the one it measured closest.
	Relay string
	Peers []PeerStatus
}

// Transport labels for PeerStatus.Path — how this peer's traffic is reaching it
// right now (MESH.4): straight over a punched UDP path, or via the relay.
const (
	PathDirect = "direct"
	PathRelay  = "relay"
)

// PeerStatus is one peer's live WireGuard state.
type PeerStatus struct {
	PublicKey        string   // base64 node key
	AllowedIPs       []string // routed prefixes (peer's /32, plus subnet routes later)
	LastHandshakeSec int64    // unix seconds of the last completed handshake; 0 = never
	RxBytes          int64
	TxBytes          int64
	// Path is PathDirect while hole punching has a validated path to this peer,
	// PathRelay otherwise. It is the transport the NEXT packet would take, not a
	// historical record — a path that goes stale flips back to relay on its own.
	Path string
	// Endpoint is where this peer's traffic is going: the direct UDP endpoint when
	// Path is PathDirect, otherwise the address of the relay the peer homes at
	// (which, in a fleet, is not necessarily our own).
	Endpoint string
}

// parseUAPI turns a wireguard-go IpcGet() dump into per-peer status. The dump is
// newline-separated key=value; each `public_key=` line starts a new peer. UAPI
// peer keys are hex, so we re-encode to base64 to match how node keys appear
// everywhere else (coordinator, `wg show`).
func parseUAPI(dump string) []PeerStatus {
	var peers []PeerStatus
	var cur *PeerStatus
	for _, line := range strings.Split(dump, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			peers = append(peers, PeerStatus{PublicKey: hexToBase64(v)})
			cur = &peers[len(peers)-1]
		case "allowed_ip":
			if cur != nil {
				cur.AllowedIPs = append(cur.AllowedIPs, v)
			}
		case "last_handshake_time_sec":
			if cur != nil {
				cur.LastHandshakeSec, _ = strconv.ParseInt(v, 10, 64)
			}
		case "rx_bytes":
			if cur != nil {
				cur.RxBytes, _ = strconv.ParseInt(v, 10, 64)
			}
		case "tx_bytes":
			if cur != nil {
				cur.TxBytes, _ = strconv.ParseInt(v, 10, 64)
			}
		}
	}
	return peers
}

func hexToBase64(h string) string {
	b, err := hex.DecodeString(h)
	if err != nil {
		return h
	}
	return base64.StdEncoding.EncodeToString(b)
}
