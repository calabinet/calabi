package main

import (
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
)

// env.go - the coordinator's configuration namespace.
//
// Every setting is CALABI_COORD_*. The old COORD_SVC_* names still work and are
// reported once at startup, by name, so an operator finds out they are relying
// on them before the day they are deleted.
//
// WHY RENAME
//
// Not cosmetics - the old scheme was already producing two different binaries
// from one source. svcboot derives its env prefix from the SERVICE NAME, and the
// public export rewrites "calabi-coord" to "calabi-coord". So the same file
// compiled here read COORD_SVC_GRPC_ADDR and, in the public tree, read
// CALABI_COORD_GRPC_ADDR - while every doc comment in both trees said
// COORD_SVC_*. A self-hoster following the published comments would have set a
// variable the published binary never reads.
//
// That is exactly the fork 7.3 warned about ("环境变量一改，公开树和私有树的运行时
// 行为就分叉"), and the fix it prescribed: rename in the PRIVATE source so both
// trees read the same names, rather than letting the export change behaviour.
// svcboot.Options.EnvPrefix now states the prefix explicitly for the same
// reason - a prefix derived from branding is a config change waiting to happen.
//
// WHY CALABI_COORD_ AND NOT COORD_SVC_: "-svc" is internal shorthand for "one of
// our control-plane services". The coordinator ships to people who run it alone;
// to them it is not a service in a fleet, it is the program.

// envPrefix / legacyEnvPrefix are the two namespaces, as literals rather than
// anything derived from serviceName - deriving them is what broke.
const (
	envPrefix       = "CALABI_COORD"
	legacyEnvPrefix = "COORD_SVC"
)

var (
	legacyMu   sync.Mutex
	legacySeen = map[string]string{} // old name -> new name
)

// env returns the value of CALABI_COORD_<suffix>, falling back to
// COORD_SVC_<suffix>. Suffix is given without the leading underscore.
//
// Trims whitespace, so a var set to "   " counts as unset - the same rule
// svcboot applies, and the difference between "unset" and "blank" is never what
// an operator meant.
func env(suffix string) string {
	if v := strings.TrimSpace(os.Getenv(envPrefix + "_" + suffix)); v != "" {
		return v
	}
	old := legacyEnvPrefix + "_" + suffix
	if v := strings.TrimSpace(os.Getenv(old)); v != "" {
		noteLegacy(old, envPrefix+"_"+suffix)
		return v
	}
	return ""
}

// envAlias is env() for a variable whose old name did NOT follow the
// COORD_SVC_ pattern - QUOTA_SVC_ADDR is the only one. It kept a platform
// service's name inside the coordinator's own configuration, which reads as an
// instruction to run quota-svc; under CALABI_COORD_QUOTA_ADDR it reads as what
// it is, an optional integration point.
func envAlias(suffix, oldName string) string {
	if v := strings.TrimSpace(os.Getenv(envPrefix + "_" + suffix)); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv(oldName)); v != "" {
		noteLegacy(oldName, envPrefix+"_"+suffix)
		return v
	}
	return ""
}

// envIsTrue reports whether a coordinator flag is set to a truthy value.
func envIsTrue(suffix string) bool {
	v := env(suffix)
	return v == "1" || strings.EqualFold(v, "true")
}

// envIsSet reports whether either name carries a value. Used by the production
// guard, which asks "did the operator configure this at all", not "what is it".
func envIsSet(suffix string) bool { return env(suffix) != "" }

func noteLegacy(old, current string) {
	legacyMu.Lock()
	legacySeen[old] = current
	legacyMu.Unlock()
}

// reportLegacyEnv logs every deprecated name that actually supplied a value.
//
// Once, at the end of configuration, rather than at each read: several settings
// are read more than once, and a warning that repeats is a warning people filter
// out. Nothing is logged when the deployment is already on the new names.
func reportLegacyEnv(logger *slog.Logger) {
	legacyMu.Lock()
	pairs := make([][2]string, 0, len(legacySeen))
	for old, cur := range legacySeen {
		pairs = append(pairs, [2]string{old, cur})
	}
	legacyMu.Unlock()
	if len(pairs) == 0 {
		return
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i][0] < pairs[j][0] })
	for _, p := range pairs {
		logger.Warn("using a DEPRECATED env var; rename it", "deprecated", p[0], "use", p[1])
	}
}
