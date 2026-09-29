package mesh

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/calabinet/calabi/apps/client/internal/trust"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// TLS to relays.
//
// The relay map says, per relay, whether it speaks TLS on its DERP port and how
// its certificate is checked — the ways this node already checks an edge
// (internal/trust). A relay it marks TLS is only ever dialed over TLS: a check
// that fails is a failed dial, retried like any other, never a reason to try
// plaintext, which would hand whoever blocks the TLS a downgrade. A relay it
// does not mark keeps the plaintext protocol, which every relay still speaks.

// relayTrustUnnamed stands for a map entry that says TLS but names no trust. It
// must not read as plaintext, and relayTLSConfig knows no such trust.
const relayTrustUnnamed = "(unnamed)"

// errPlatformTrustElsewhere refuses a relay that asks to be checked against the
// CA compiled into this client when the coordinator is not calabi.net: a
// self-hosted mesh must never trust that CA (internal/trust), whatever its map
// says.
var errPlatformTrustElsewhere = errors.New("the relay map asks for the calabi.net CA, and this device is not signed in to calabi.net")

// relayTLSConfig is how to dial a relay the map marks TLS. platform says this
// node's coordinator is calabi.net — the only one whose "platform" it takes.
func relayTLSConfig(addr string, t RelayTLS, platform bool) (*tls.Config, error) {
	var tc trust.Config
	switch t.Trust {
	case meshproto.RelayTrustPlatform:
		if !platform {
			return nil, errPlatformTrustElsewhere
		}
		tc = trust.Config{Mode: trust.Platform}
	case meshproto.RelayTrustSystem:
		tc = trust.Config{Mode: trust.System}
	case meshproto.RelayTrustPin:
		tc = trust.Config{Mode: trust.Pin, Pins: t.Pins}
	default:
		return nil, fmt.Errorf("the relay map names trust %q for this relay, which this client does not know; update calabi", t.Trust)
	}
	cfg, err := tc.TLS(addr)
	if err != nil {
		return nil, err
	}
	if cfg == nil { // no trust above is plaintext; never let one turn into it
		return nil, errors.New("relay trust resolved to no TLS")
	}
	return cfg, nil
}

// relayTLSByAddr lists, by the address the pool dials (host:port), every relay
// the map marks TLS.
func relayTLSByAddr(m DERPMap) map[string]RelayTLS {
	out := map[string]RelayTLS{}
	for _, r := range m.Regions {
		for _, n := range r.Nodes {
			if n.HostName == "" || n.DERPPort <= 0 || !n.TLS.Enabled() {
				continue
			}
			out[net.JoinHostPort(n.HostName, strconv.Itoa(n.DERPPort))] = n.TLS
		}
	}
	return out
}
