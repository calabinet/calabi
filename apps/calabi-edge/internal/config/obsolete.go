package config

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// checkRemovedTokens refuses a token table the edge no longer reads. The static
// accepted_tokens table is gone: a
// self-hosted edge accepts devices by its coordinator's grants, and the platform
// by bff-edge. An empty table — how every platform edge's file says "none" —
// still loads. A list of tokens is refused: parsing it silently would leave an
// operator believing the clients holding them can still connect.
func checkRemovedTokens(data []byte) error {
	var old struct {
		AcceptedTokens []yaml.Node `yaml:"accepted_tokens"`
	}
	if err := yaml.Unmarshal(data, &old); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	if len(old.AcceptedTokens) == 0 {
		return nil
	}
	return fmt.Errorf("accepted_tokens lists %d token(s), but the edge no longer accepts tokens: devices join the "+
		"coordinator (an invite) and the edge accepts them by its grants. Set mode: standalone and the "+
		"coordinator's key (coord_pubkey or coord_pubkey_file), and remove accepted_tokens", len(old.AcceptedTokens))
}

// The dead direct-dial settings that used to be listed here (identity.addr,
// tunnel.addr, cert.addr, quota.addr, config_svc.addr, and the whole nats:
// block) are refused by layout.go now, which sees the raw document and can
// therefore name a block that no longer has a struct to parse into.
