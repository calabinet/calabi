package localweb

// features_platform.go — platform-edition local-console capabilities. A
// self-hosted edge has no per-plan gate, so every per-tunnel security section
// is available in the local console's editor.

// standaloneFeatures enables every per-tunnel security capability (the SPA
// reads this as plan.features_json to decide which editor sections to show).
const standaloneFeatures = `{"ip_policy":true,"basic_auth":true,"rate_limit":true,"header_rewrite":true,"oauth":true,"tcp":true,"udp":true,"sni":true,"custom_domain":true}`

// stripAdvancedSecurity is a no-op on the platform build — all features apply.
func stripAdvancedSecurity(map[string]any) {}
