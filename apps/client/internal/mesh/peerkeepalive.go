package mesh

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// SetPeerKeepalive changes exactly one existing WireGuard peer. It does not
// recreate peers, reset traffic counters or force unrelated handshakes. Zero
// explicitly disables the interval. Overrides survive unchanged netmap refreshes
// and are discarded when the peer is removed.
func (d *WGDatapath) SetPeerKeepalive(key meshproto.NodeKey, every time.Duration) error {
	if every < 0 || every%time.Second != 0 || every > 65535*time.Second {
		return fmt.Errorf("mesh: invalid peer keepalive interval")
	}
	d.peerConfigMu.Lock()
	defer d.peerConfigMu.Unlock()
	if d.configClosed {
		return fmt.Errorf("mesh: datapath closed")
	}
	if !d.knownPeers[key] || d.dev == nil {
		return fmt.Errorf("mesh: unknown keepalive peer")
	}
	hexKey := hex.EncodeToString(key[:])
	if err := d.dev.IpcSet(fmt.Sprintf("public_key=%s\nupdate_only=true\npersistent_keepalive_interval=%d\n", hexKey, int(every/time.Second))); err != nil {
		return fmt.Errorf("mesh: update peer keepalive: %w", err)
	}
	if d.keepaliveOverrides == nil {
		d.keepaliveOverrides = make(map[meshproto.NodeKey]time.Duration)
	}
	d.keepaliveOverrides[key] = every
	d.lastPeerConf = rewritePeerKeepalive(d.lastPeerConf, hexKey, int(every/time.Second))
	return nil
}

func rewritePeerKeepalive(conf, key string, seconds int) string {
	lines := strings.Split(strings.TrimSuffix(conf, "\n"), "\n")
	out := make([]string, 0, len(lines)+1)
	inPeer := false
	flush := func() {
		if inPeer && seconds > 0 {
			out = append(out, fmt.Sprintf("persistent_keepalive_interval=%d", seconds))
		}
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "public_key=") {
			flush()
			inPeer = line == "public_key="+key
		}
		if inPeer && strings.HasPrefix(line, "persistent_keepalive_interval=") {
			continue
		}
		out = append(out, line)
	}
	flush()
	return strings.Join(out, "\n") + "\n"
}
