package adminhttp_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/adminhttp"
	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
)

// relayCoord is a coordinator with a relay registry, signing grants with key
// when key is non-nil.
func relayCoord(key ed25519.PrivateKey) *core.Coordinator {
	c := newContractCoord()
	relays := core.NewMemRelayStore()
	c.Relays = relays
	c.DERP = core.CompositeDERP{
		Platform: core.DERPMap{Regions: []core.DERPRegion{{Code: "lax"}}},
		Relays:   relays,
	}
	if key != nil {
		c.RelayGrants = &core.SigningRelayGrantIssuer{Key: key}
	}
	return c
}

func relayRequest(t *testing.T, h http.Handler, method string) map[string]any {
	t.Helper()
	rr := httptest.NewRecorder()
	body := `{"label":"tokyo","host_name":"relay1.example","derp_port":3340,"stun_port":3478}`
	h.ServeHTTP(rr, httptest.NewRequest(method, "/admin/meshnets/7/relays", strings.NewReader(body)))
	if rr.Code/100 != 2 {
		t.Fatalf("%s relays: status %d (%s)", method, rr.Code, rr.Body.String())
	}
	var view map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return view
}

// A relay that registers itself learns, in the same answer, the key its devices'
// grants are signed with — it has no other way to learn it, and without it the
// relay cannot tell its organization's devices from anyone else.
func TestRelaySelfRegistrationReturnsGrantKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := adminhttp.New(relayCoord(priv), core.NewNotifier(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Twice: the first registers, the second is the steady-state heartbeat —
	// which has to carry the key too, or a relay that restarts after its first
	// registration would never learn it.
	for i := 0; i < 2; i++ {
		view := relayRequest(t, h, http.MethodPut)
		if got := view["grant_pubkey"]; got != base64.StdEncoding.EncodeToString(pub) {
			t.Fatalf("upsert #%d: grant_pubkey = %v, want the coordinator's signing key", i+1, got)
		}
	}
}

// No key when the coordinator signs nothing: devices then hold no grants, and a
// relay handed a key would turn every one of them away.
func TestRelaySelfRegistrationWithoutGrantsReturnsNoKey(t *testing.T) {
	h := adminhttp.New(relayCoord(nil), core.NewNotifier(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	view := relayRequest(t, h, http.MethodPut)
	if _, ok := view["grant_pubkey"]; ok {
		t.Fatalf("grant_pubkey = %v from a coordinator that signs no grants", view["grant_pubkey"])
	}
}

// Only the relay's own registration carries it. The console's registration and
// listing are rendered for people, who have no use for it.
func TestConsoleRelayRegistrationCarriesNoGrantKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := adminhttp.New(relayCoord(priv), core.NewNotifier(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if view := relayRequest(t, h, http.MethodPost); view["grant_pubkey"] != nil {
		t.Fatalf("console registration returned grant_pubkey = %v", view["grant_pubkey"])
	}
}
