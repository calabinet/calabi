package main

import (
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
)

// meshAdminSettings is the resolved posture of the mesh-admin HTTP surface,
// decided ONCE at startup (main) so a misconfiguration aborts the process
// instead of quietly serving an unauthenticated ops API.
type meshAdminSettings struct {
	// Addr is CALABI_COORD_MESH_ADMIN_ADDR. Empty = the surface is not served at
	// all (the default — no port is opened).
	Addr string
	// Token is the shared bearer secret every caller must present. Empty is
	// legal ONLY when AllowNoAuth was explicitly opted into.
	Token string
	// AllowNoAuth records that the operator deliberately ran the surface with no
	// authentication (local dev / smoke stacks).
	AllowNoAuth bool
}

// resolveMeshAdmin reads the mesh-admin configuration and FAILS CLOSED.
//
// Why this is a hard error rather than a warning: /admin/* is the whole mesh
// control surface — approve or delete any node, rewrite any meshnet's ACL,
// register a relay — and it carries no authorization of its own. Its tenant
// boundary is the meshnet id in the PATH, which the calling gateway
// (bff-console / bff-admin / bff-edge) fills in from the authenticated user.
// So whoever can reach this port IS an admin of every meshnet. Serving it with
// no credential check is only ever a local-dev posture; in any deployment where
// something else shares the network it is a cross-org takeover waiting for one
// compromised container.
//
// Not bound to loopback by design: in the compose topology the gateways run in
// SEPARATE containers and reach coord over the bridge network, so 127.0.0.1
// would break them while providing no protection the token doesn't already
// give. The surface is already unpublished (no host port mapping); the token is
// what defends it from anything else on that network.
func resolveMeshAdmin() (meshAdminSettings, error) {
	s := meshAdminSettings{
		Addr:        env("MESH_ADMIN_ADDR"),
		Token:       env("MESH_ADMIN_TOKEN"),
		AllowNoAuth: envIsTrue("MESH_ADMIN_ALLOW_NOAUTH"),
	}
	if s.Addr == "" {
		// Surface disabled. Any token/opt-in is irrelevant.
		return meshAdminSettings{}, nil
	}
	if s.Token == "" && !s.AllowNoAuth {
		return meshAdminSettings{}, fmt.Errorf(
			"CALABI_COORD_MESH_ADMIN_ADDR=%s serves the mesh-admin API, but CALABI_COORD_MESH_ADMIN_TOKEN is empty: "+
				"that API can approve/delete any node and rewrite any meshnet's ACL, so it is never served "+
				"unauthenticated by accident. Set CALABI_COORD_MESH_ADMIN_TOKEN (and the matching "+
				"*_COORD_ADMIN_TOKEN on bff-console / bff-admin / bff-edge), or set "+
				"CALABI_COORD_MESH_ADMIN_ALLOW_NOAUTH=1 for a local dev stack", s.Addr)
	}
	return s, nil
}

// meshAdminAuth gates h on the shared bearer token. Every /admin/* route is
// covered — there is no health/exempt path, because the surface itself is
// private and its liveness is already covered by the svcboot admin port.
func meshAdminAuth(token string, h http.Handler) http.Handler {
	const scheme = "Bearer "
	want := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := r.Header.Get("Authorization")
		var got []byte
		if strings.HasPrefix(hdr, scheme) {
			got = []byte(hdr[len(scheme):])
		}
		// ConstantTimeCompare returns 0 on a length mismatch too, so this is the
		// whole check — but it is NOT constant time across differing lengths,
		// which is fine for a high-entropy shared secret.
		if subtle.ConstantTimeCompare(got, want) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// logMeshAdminPosture states the decision in the startup log, loudly when the
// surface is running without authentication.
func (s meshAdminSettings) logPosture(logger *slog.Logger) {
	switch {
	case s.Addr == "":
		return
	case s.Token != "":
		logger.Info("coord mesh-admin HTTP up (private ops surface, bearer token required)", "addr", s.Addr)
	default:
		logger.Warn("coord mesh-admin HTTP up with NO AUTHENTICATION "+
			"(CALABI_COORD_MESH_ADMIN_ALLOW_NOAUTH=1) — anyone who can reach this port controls every meshnet; "+
			"never do this outside a local dev stack", "addr", s.Addr)
	}
}

// envTrue reads a boolean env var the same way the rest of the fleet does.
func envTrue(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
