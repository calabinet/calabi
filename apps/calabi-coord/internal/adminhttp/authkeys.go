package adminhttp

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
)

// Auth keys a self-hosted coordinator mints — what `calabi-coord authkey` and
// `calabi-coord invite` call.
// A coordinator whose credentials come from an identity service has none, and
// answers 404 for all three routes.

// maxAuthKeyTTL caps how far out an expiry may be set. A key that never expires
// is asked for by name (no_expiry); this only stops a typo from minting a
// century-long one.
const maxAuthKeyTTL = 10 * 365 * 24 * time.Hour

type authKeyView struct {
	ID          int64    `json:"id"`
	Prefix      string   `json:"prefix"`
	Tags        []string `json:"tags"`
	MaxUses     int      `json:"max_uses"`
	Uses        int      `json:"uses"`
	ExpiresAtMS int64    `json:"expires_at_ms,omitempty"`
	RevokedAtMS int64    `json:"revoked_at_ms,omitempty"`
	CreatedAtMS int64    `json:"created_at_ms"`
	Note        string   `json:"note,omitempty"`
	// Key is the key itself — only in the answer to the POST that created it.
	Key string `json:"key,omitempty"`
}

func toAuthKeyView(k *core.AuthKey) authKeyView {
	v := authKeyView{
		ID: k.ID, Prefix: k.Prefix, Tags: k.Tags, MaxUses: k.MaxUses, Uses: k.Uses,
		CreatedAtMS: k.CreatedAt.UnixMilli(), Note: k.Note,
	}
	if v.Tags == nil {
		v.Tags = []string{}
	}
	if !k.ExpiresAt.IsZero() {
		v.ExpiresAtMS = k.ExpiresAt.UnixMilli()
	}
	if !k.RevokedAt.IsZero() {
		v.RevokedAtMS = k.RevokedAt.UnixMilli()
	}
	return v
}

// listenerTLS reports what the gRPC listener serves, for invite links.
func (h *handler) listenerTLS(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"mode": h.coord.ListenerTLS.Mode, "pin": h.coord.ListenerTLS.Pin})
}

// authKeys answers 404 when this coordinator mints no keys.
func (h *handler) authKeys(w http.ResponseWriter) (core.AuthKeyStore, bool) {
	if h.coord.AuthKeys == nil {
		http.Error(w, "this coordinator does not mint auth keys: its credentials come from an identity service", http.StatusNotFound)
		return nil, false
	}
	return h.coord.AuthKeys, true
}

// createAuthKey mints a key. Body: {"max_uses": 1, "expires_in_seconds": 86400,
// "tags": ["tag:phone"], "note": "Alice's phone"}; every field optional, and
// the defaults are what an invite should be — one use, one day. Unlimited
// uses: max_uses 0 with "reusable": true; no expiry: "expires_in_seconds": 0
// with "no_expiry": true. Both have to be asked for by name.
func (h *handler) createAuthKey(w http.ResponseWriter, r *http.Request) {
	store, ok := h.authKeys(w)
	if !ok {
		return
	}
	meshnet, ok := meshnetFromPath(w, r)
	if !ok {
		return
	}
	var in struct {
		MaxUses          *int     `json:"max_uses"`
		Reusable         bool     `json:"reusable"`
		ExpiresInSeconds *int64   `json:"expires_in_seconds"`
		NoExpiry         bool     `json:"no_expiry"`
		Tags             []string `json:"tags"`
		Note             string   `json:"note"`
	}
	if r.ContentLength != 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&in); err != nil {
			http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	secret, k, err := core.NewAuthKey(meshnet)
	if err != nil {
		http.Error(w, "mint: "+err.Error(), http.StatusInternalServerError)
		return
	}

	k.MaxUses = 1
	switch {
	case in.Reusable && in.MaxUses != nil && *in.MaxUses != 0:
		http.Error(w, "reusable means no use limit; drop max_uses or reusable", http.StatusBadRequest)
		return
	case in.Reusable:
		k.MaxUses = 0
	case in.MaxUses != nil && *in.MaxUses < 1:
		http.Error(w, "max_uses must be 1 or more (for any number of devices, send reusable: true)", http.StatusBadRequest)
		return
	case in.MaxUses != nil:
		k.MaxUses = *in.MaxUses
	}

	ttl := 24 * time.Hour
	switch {
	case in.NoExpiry && in.ExpiresInSeconds != nil && *in.ExpiresInSeconds != 0:
		http.Error(w, "no_expiry and expires_in_seconds contradict each other", http.StatusBadRequest)
		return
	case in.NoExpiry:
		ttl = 0
	case in.ExpiresInSeconds == nil:
		// the default above
	case *in.ExpiresInSeconds <= 0:
		http.Error(w, "expires_in_seconds must be positive (for a key that never expires, send no_expiry: true)", http.StatusBadRequest)
		return
	case *in.ExpiresInSeconds > int64(maxAuthKeyTTL/time.Second):
		// Compared in seconds: multiplied out first, a large enough value
		// overflows a Duration and wraps to something that passes.
		ttl = maxAuthKeyTTL + 1
	default:
		ttl = time.Duration(*in.ExpiresInSeconds) * time.Second
	}
	if ttl > maxAuthKeyTTL {
		http.Error(w, "expires_in_seconds is more than ten years; for a key that never expires, send no_expiry: true", http.StatusBadRequest)
		return
	}
	if ttl > 0 {
		k.ExpiresAt = time.Now().Add(ttl).UTC()
	}

	for _, tag := range in.Tags {
		if !strings.HasPrefix(tag, "tag:") || len(tag) == len("tag:") {
			http.Error(w, "tags look like tag:<name>: "+tag, http.StatusBadRequest)
			return
		}
	}
	k.Tags, k.Note = in.Tags, strings.TrimSpace(in.Note)

	saved, err := store.CreateAuthKey(r.Context(), k)
	if err != nil {
		http.Error(w, "store: "+err.Error(), http.StatusInternalServerError)
		return
	}
	v := toAuthKeyView(saved)
	v.Key = secret
	h.logger.Info("auth key minted", "meshnet", meshnet, "id", saved.ID, "prefix", saved.Prefix, "max_uses", saved.MaxUses, "expires_at", saved.ExpiresAt)
	writeJSON(w, http.StatusCreated, v)
}

func (h *handler) listAuthKeys(w http.ResponseWriter, r *http.Request) {
	store, ok := h.authKeys(w)
	if !ok {
		return
	}
	meshnet, ok := meshnetFromPath(w, r)
	if !ok {
		return
	}
	keys, err := store.ListAuthKeys(r.Context(), meshnet)
	if err != nil {
		http.Error(w, "list: "+err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]authKeyView, 0, len(keys))
	for _, k := range keys {
		out = append(out, toAuthKeyView(k))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// revokeAuthKey refuses the key from now on. Devices it already admitted stay:
// to remove one, disable or delete the node.
func (h *handler) revokeAuthKey(w http.ResponseWriter, r *http.Request) {
	store, ok := h.authKeys(w)
	if !ok {
		return
	}
	meshnet, ok := meshnetFromPath(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("keyID"), 10, 64)
	if err != nil {
		http.Error(w, "bad key id", http.StatusBadRequest)
		return
	}
	if err := store.RevokeAuthKey(r.Context(), meshnet, id); err != nil {
		if errors.Is(err, core.ErrAuthKeyNotFound) {
			http.Error(w, "auth key not found in this meshnet", http.StatusNotFound)
			return
		}
		http.Error(w, "revoke: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.logger.Info("auth key revoked", "meshnet", meshnet, "id", id)
	w.WriteHeader(http.StatusNoContent)
}
