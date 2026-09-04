package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestResolveMeshAdminFailsClosed pins the security decision: the mesh-admin
// surface — which can approve/delete any node and rewrite any meshnet's ACL —
// is never served without a token by accident. Only an explicit opt-in env
// allows it, and only for local dev.
func TestResolveMeshAdminFailsClosed(t *testing.T) {
	cases := []struct {
		name       string
		addr       string
		token      string
		allowNone  string
		wantErr    bool
		wantToken  string
		wantNoAuth bool
	}{
		{name: "surface off: nothing required", addr: "", wantErr: false},
		{name: "surface off ignores a stray opt-in", addr: "", allowNone: "1", wantErr: false},
		{name: "addr without token REFUSES to start", addr: ":9500", wantErr: true},
		{name: "addr with token is authenticated", addr: ":9500", token: "s3cret", wantToken: "s3cret"},
		{name: "explicit opt-in allows no auth", addr: ":9500", allowNone: "1", wantNoAuth: true},
		{name: "opt-in accepts true as well", addr: ":9500", allowNone: "true", wantNoAuth: true},
		{name: "junk opt-in is not an opt-in", addr: ":9500", allowNone: "please", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("CALABI_COORD_MESH_ADMIN_ADDR", c.addr)
			t.Setenv("CALABI_COORD_MESH_ADMIN_TOKEN", c.token)
			t.Setenv("CALABI_COORD_MESH_ADMIN_ALLOW_NOAUTH", c.allowNone)

			got, err := resolveMeshAdmin()
			if c.wantErr {
				if err == nil {
					t.Fatalf("resolveMeshAdmin() = %+v, want an error (an unauthenticated admin surface must abort startup)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveMeshAdmin() error = %v, want nil", err)
			}
			if got.Addr != c.addr {
				t.Errorf("Addr = %q, want %q", got.Addr, c.addr)
			}
			if got.Token != c.wantToken {
				t.Errorf("Token = %q, want %q", got.Token, c.wantToken)
			}
			if got.AllowNoAuth != c.wantNoAuth {
				t.Errorf("AllowNoAuth = %v, want %v", got.AllowNoAuth, c.wantNoAuth)
			}
		})
	}
}

// TestMeshAdminAuth covers the gate itself: only an exact "Bearer <token>"
// passes. Every other shape is 401 — including the bare token, so the wire
// contract stays unambiguous for the gateways (coordadmin always sends Bearer).
func TestMeshAdminAuth(t *testing.T) {
	const token = "tok-abc123"
	var reached bool
	h := meshAdminAuth(token, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusNoContent)
	}))

	cases := []struct {
		name   string
		header string
		want   int
	}{
		{name: "correct bearer", header: "Bearer " + token, want: http.StatusNoContent},
		{name: "no header", header: "", want: http.StatusUnauthorized},
		{name: "wrong token", header: "Bearer nope", want: http.StatusUnauthorized},
		{name: "empty bearer", header: "Bearer ", want: http.StatusUnauthorized},
		{name: "bare token without scheme", header: token, want: http.StatusUnauthorized},
		{name: "wrong scheme", header: "Basic " + token, want: http.StatusUnauthorized},
		{name: "prefix of the token", header: "Bearer " + token[:4], want: http.StatusUnauthorized},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reached = false
			req := httptest.NewRequest(http.MethodDelete, "/admin/meshnets/1/nodes/2", nil)
			if c.header != "" {
				req.Header.Set("Authorization", c.header)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != c.want {
				t.Errorf("status = %d, want %d", rec.Code, c.want)
			}
			if wantReached := c.want == http.StatusNoContent; reached != wantReached {
				t.Errorf("handler reached = %v, want %v (an unauthorized request must never touch the admin handler)", reached, wantReached)
			}
		})
	}
}
