package config

import "fmt"

// Notes are the things a load noticed that are worth saying out loud but are
// not reasons to refuse the boot. This package has no logger on purpose (it is
// imported by the hot-reloader, by tests and by tooling), so it hands them back
// and the caller logs them.
//
// It replaced a bare `byoiRefused bool` return the day a second such
// observation appeared. A third one should land in here too rather than
// becoming a third return value nobody reads.
type Notes struct {
	// BYOIRefused reports that mode=standalone was overridden because the edge
	// holds a control-plane cert.
	BYOIRefused bool
	// Warnings are one-line, operator-facing, and safe to print verbatim.
	Warnings []string
}

// LoadEffective turns a config path into the config the process actually runs
// with: the file (Load), environment overrides (ApplyEnv), mode normalization
// (NormalizeForMode), this node's identity from its own certificate
// (resolveCertIdentity), and the checks that must pass before anything binds
// (ValidateRole, ValidateClientAuth, ValidateProductionPosture).
//
// Boot AND hot-reload go through this one function. They used to be two copies:
// boot ran every step, reload ran only Load. So an env override of any field the
// reloader compares (CALABI_EDGE_MODE, CALABI_EDGE_ADMIN_ADDR, …) made the
// reloaded file look different from the running config and every reload was
// refused, while the production posture check never saw a reloaded token table
// at all. A step added to one path and not the other brings both bugs back —
// add it here.
func LoadEffective(path string) (cfg Config, notes Notes, err error) {
	cfg, raw, err := loadWithRaw(path)
	if err != nil {
		return Config{}, Notes{}, fmt.Errorf("load config: %w", err)
	}
	// Self-hosters often run without a config file at all — a relay-only node has
	// no domain, no certificate and nothing else to configure. Env overrides for
	// mode / role / the relay block keep that possible now that the standalone
	// derp-node binary (which was ENTIRELY env-driven) is retired. Env wins over
	// the file. See env.go.
	cfg, err = ApplyEnv(cfg)
	if err != nil {
		return Config{}, Notes{}, err
	}
	// One coordinator key, whichever spelling (file, env, the relay block) gave it.
	if err := resolveCoordPubKey(&cfg); err != nil {
		return Config{}, Notes{}, err
	}
	// Standalone normalization: a self-hosted (mode=standalone) edge has no
	// control plane, so its control-plane addresses are cleared; a BYOI edge
	// (bff-edge cert) is refused standalone and kept on platform semantics.
	// See NormalizeForMode +
	cfg, notes.BYOIRefused = cfg.NormalizeForMode()
	// Who this node is, from its own mTLS certificate — the same certificate
	// bff-edge authenticates it by, so the two cannot disagree. Runs here, in
	// the shared pipeline, and NOT in main: the hot-reloader diffs a fresh
	// LoadEffective against the boot one, so an identity derived anywhere else
	// would show up as a changed field on every reload and refuse it.
	// See certidentity.go.
	warnings, err := resolveCertIdentity(&cfg, raw)
	if err != nil {
		return Config{}, notes, err
	}
	notes.Warnings = append(notes.Warnings, warnings...)
	// Role selects which data plane(s) run (edge/derp merge). Reject a typo now
	// rather than silently run neither. Empty defaults to "edge" (unchanged).
	if err := cfg.ValidateRole(); err != nil {
		return Config{}, notes, err
	}
	// An edge with no way to accept a client serves nobody: bff-edge on the
	// platform, the coordinator's key everywhere else. Checked after
	// normalization: a standalone edge keeping bff-edge is flipped back to
	// platform above, and then bff-edge verifies clients.
	if err := cfg.ValidateClientAuth(); err != nil {
		return Config{}, notes, err
	}
	// A node that serves tunnels has to say where it can be reached: the dial
	// string in the edge directory is public.host plus tunnel.control_port, and
	// the self-signed control certificate is issued for that host. There is no
	// fallback — the bind address it used to fall back to said ":7443", which is
	// a dial string only on the one machine that is also the client.
	//
	// After ValidateClientAuth, not before: a node that can admit nobody has a
	// more fundamental problem than not saying where it is, and reporting the
	// address first would bury it.
	if err := cfg.ValidatePublicHost(); err != nil {
		return Config{}, notes, err
	}
	// CALABI_ENV=production: none of the dev fallbacks (no control plane where
	// one was meant, an ungranted platform relay) may be active. Checked AFTER NormalizeForMode so "no control plane" reads as the
	// stated standalone intent rather than a missing dependency.
	// prodguard.go + F0.2.
	if err := cfg.ValidateProductionPosture(); err != nil {
		return Config{}, notes, err
	}
	return cfg, notes, nil
}
