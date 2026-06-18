package session

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// formatID returns "<prefix>-<seq>" -- predictable, easy to grep in logs.
func formatID(prefix string, seq uint64) string {
	return fmt.Sprintf("%s-%06d", prefix, seq)
}

// randomID returns "<prefix>-<8 hex>" for non-sequential identifiers
// (e.g. assigned-domain subdomains).
func randomID(prefix string) string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(b[:]))
}

// ProxyID mints a proxy ID for use in NEW_PROXY_RESP.
func ProxyID() string { return randomID("px") }
