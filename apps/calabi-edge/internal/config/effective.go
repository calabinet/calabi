package config

import "fmt"

// LoadEffective turns a config path into the config the process actually runs
// with: the file (Load), environment overrides (ApplyEnv), mode normalization
// (NormalizeForMode), and the checks that must pass before anything binds
// (ValidateRole, ValidateClientAuth, ValidateProductionPosture). byoiRefused reports that
// mode=standalone was overridden because the edge holds a control-plane cert;
// the caller logs it (this package has no logger).
//
// Boot AND hot-reload go through this one function. They used to be two copies:
// boot ran every step, reload ran only Load. So an env override of any field the
// reloader compares (CALABI_EDGE_MODE, CALABI_EDGE_ADMIN_ADDR, …) made the
// reloaded file look different from the running config and every reload was
// refused, while the production posture check never saw a reloaded token table
// at all. A step added to one path and not the other brings both bugs back —
// add it here.
func LoadEffective(path string) (cfg Config, byoiRefused bool, err error) {
	cfg, err = Load(path)
	if err != nil {
		return Config{}, false, fmt.Errorf("load config: %w", err)
	}
	// Self-hosters often run without a config file at all — a relay-only node has
	// no domain, no certificate and nothing else to configure. Env overrides for
	// mode / role / the relay block keep that possible now that the standalone
	// derp-node binary (which was ENTIRELY env-driven) is retired. Env wins over
	// the file. See env.go.
	cfg, err = ApplyEnv(cfg)
	if err != nil {
		return Config{}, false, err
	}
	// One coordinator key, whichever spelling (file, env, the relay block) gave it.
	if err := resolveCoordPubKey(&cfg); err != nil {
		return Config{}, false, err
	}
	// Standalone normalization: a self-hosted (mode=standalone) edge has no
	// control plane, so its control-plane addresses are cleared; a BYOI edge
	// (bff-edge cert) is refused standalone and kept on platform semantics.
	// See NormalizeForMode +
	cfg, byoiRefused = cfg.NormalizeForMode()
	// Role selects which data plane(s) run (edge/derp merge). Reject a typo now
	// rather than silently run neither. Empty defaults to "edge" (unchanged).
	if err := cfg.ValidateRole(); err != nil {
		return Config{}, byoiRefused, err
	}
	// An edge with no way to accept a client serves nobody: bff-edge on the
	// platform, the coordinator's key everywhere else. Checked after
	// normalization: a standalone edge keeping bff-edge is flipped back to
	// platform above, and then bff-edge verifies clients.
	if err := cfg.ValidateClientAuth(); err != nil {
		return Config{}, byoiRefused, err
	}
	// CALABI_ENV=production: none of the dev fallbacks (no control plane where
	// one was meant, an ungranted platform relay) may be active. Checked AFTER NormalizeForMode so "no control plane" reads as the
	// stated standalone intent rather than a missing dependency.
	// prodguard.go + F0.2.
	if err := cfg.ValidateProductionPosture(); err != nil {
		return Config{}, byoiRefused, err
	}
	return cfg, byoiRefused, nil
}
