package policy

// A Policy in this build carries only IP allow/deny and HTTP Basic auth (parsed
// in policy.go). It does not enforce connection rate limiting, request-header
// rewrite, or an OAuth login wall, so the methods below report "off" / pass
// through and a config_json block for any of those is ignored. `advanced` holds
// no state.

import (
	"io"
	"time"
)

type advanced struct{}

// parseAdvanced does nothing here — there are no advanced features to populate.
func (p *Policy) parseAdvanced(string) bool { return false }

// No connection-rate cap.
func (p *Policy) HasRateLimit() bool { return false }
func (p *Policy) AllowRate() bool    { return true }

// No request-header rewrite.
func (p *Policy) HasRequestHeaders() bool               { return false }
func (p *Policy) RewriteRequestHead(head []byte) []byte { return head }

// No OAuth login wall.
func (p *Policy) HasOAuth() bool { return false }
func (p *Policy) GateOAuth(_ io.Writer, _, _ string, _ bool, _ string, _ time.Time) bool {
	return false
}
