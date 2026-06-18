package localweb

// Local-console capabilities for this build. The advanced per-tunnel access
// controls (rate limit / header rewrite / OAuth login wall) are not supported,
// so they are disabled in the capability map (the SPA hides those editor
// sections) and stripped from any submitted config. IP allow/deny + HTTP Basic
// auth are available.

// standaloneFeatures disables rate_limit / header_rewrite / oauth — the SPA
// reads this (plan.features_json) and hides those editor sections.
const standaloneFeatures = `{"ip_policy":true,"basic_auth":true,"rate_limit":false,"header_rewrite":false,"oauth":false,"tcp":true,"udp":true,"sni":true,"custom_domain":true}`

// stripAdvancedSecurity removes the unsupported blocks from a submitted
// `security` map so the console can never persist or forward them, even if a
// crafted request includes them.
func stripAdvancedSecurity(sec map[string]any) {
	delete(sec, "rate_limit")
	delete(sec, "request_headers")
	delete(sec, "oauth")
}
