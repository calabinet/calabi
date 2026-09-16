package statusapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/calabi/calabi/apps/client/internal/selfupdate"
)

// UpdateSource is the daemon's self-update agent, as the console needs it.
// *selfupdate.Agent satisfies it. Nil in Config = the endpoints 404, which is
// what a dev build, a daemon with updates disabled, and every shipped client
// older than this change all look like — so the SPA must treat 404 as "no
// information", not as an error.
type UpdateSource interface {
	Snapshot() selfupdate.Snapshot
	Check(context.Context) (selfupdate.Snapshot, error)
	Apply(context.Context) error
	Policy() selfupdate.Policy
	SetPolicy(selfupdate.Policy) (selfupdate.Snapshot, error)
}

// handleUpdateGet reports the last check. Never touches the network: the SPA
// polls this alongside everything else on the overview.
func (s *Server) handleUpdateGet(w http.ResponseWriter, _ *http.Request) {
	if s.cfg.Update == nil {
		writeError(w, http.StatusNotFound, "self-update is not configured on this daemon")
		return
	}
	writeJSON(w, http.StatusOK, s.cfg.Update.Snapshot())
}

// handleUpdateCheck re-checks now. The body is the same snapshot shape either
// way — 200 when the check ran, 502 when it could not — so the console can
// render the card from one response instead of following up with a GET.
func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Update == nil {
		writeError(w, http.StatusNotFound, "self-update is not configured on this daemon")
		return
	}
	snap, err := s.cfg.Update.Check(r.Context())
	switch {
	case errors.Is(err, selfupdate.ErrBusy):
		writeError(w, http.StatusConflict, err.Error())
	case err != nil:
		// The running install is untouched — a check that fails changes nothing.
		writeJSON(w, http.StatusBadGateway, snap)
	default:
		writeJSON(w, http.StatusOK, snap)
	}
}

// handleUpdateApply installs what the last check found.
//
// "This machine cannot install updates itself" is a 409, not a 500: it is a fact
// about the install (a user-mode daemon, a Linux box, a platform with nothing
// published) and the console turns it into "请手动更新" with a download link.
// Returning 500 would make a correct, expected state look like a malfunction.
func (s *Server) handleUpdateApply(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Update == nil {
		writeError(w, http.StatusNotFound, "self-update is not configured on this daemon")
		return
	}
	// Deliberately NOT r.Context(): the installer stops and restarts this very
	// service, so the browser's connection dies partway through by design. Tying
	// the apply to the request would cancel it the moment that happens.
	err := s.cfg.Update.Apply(context.WithoutCancel(r.Context()))
	switch {
	case errors.Is(err, selfupdate.ErrCannotApply), errors.Is(err, selfupdate.ErrBusy):
		writeJSON(w, http.StatusConflict, s.cfg.Update.Snapshot())
	case err != nil:
		writeJSON(w, http.StatusBadGateway, s.cfg.Update.Snapshot())
	default:
		writeJSON(w, http.StatusOK, s.cfg.Update.Snapshot())
	}
}

// handleUpdatePolicy changes the machine's update setting.
//
// MERGE semantics, not replace: absent fields keep their current value. A body
// of {"mode":"notify"} must not also silently wipe the maintenance window to
// 00:00–00:00 ("any time") and the defer cap to 0 ("never wait") — the two
// settings a person switching to notify-only cares about most. Same three-state
// shape the org-quota endpoints use.
//
// There is no "off" here on purpose. Turning the CHECK off is an ops decision
// (CALABI_UPDATE_MANIFEST=), deliberately not one click away in a console:
// "never check again" is how a fleet ends up permanently on a version with a
// known hole. The mode switch decides who INSTALLS, not whether we look.
func (s *Server) handleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Update == nil {
		writeError(w, http.StatusNotFound, "self-update is not configured on this daemon")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4*1024))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	var in struct {
		Mode            *string `json:"mode"`
		WindowStartHour *int    `json:"window_start_hour"`
		WindowEndHour   *int    `json:"window_end_hour"`
		MaxDeferDays    *int    `json:"max_defer_days"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		writeError(w, http.StatusBadRequest, "parse: "+err.Error())
		return
	}
	p := s.cfg.Update.Policy()
	if in.Mode != nil {
		p.Mode = *in.Mode
	}
	if in.WindowStartHour != nil {
		p.WindowStartHour = *in.WindowStartHour
	}
	if in.WindowEndHour != nil {
		p.WindowEndHour = *in.WindowEndHour
	}
	if in.MaxDeferDays != nil {
		p.MaxDeferDays = *in.MaxDeferDays
	}
	snap, err := s.cfg.Update.SetPolicy(p)
	if err != nil {
		// Validation rejects rather than repairs: a 400 naming the problem beats
		// quietly storing something the caller did not ask for.
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, snap)
}
