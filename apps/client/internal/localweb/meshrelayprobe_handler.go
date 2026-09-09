package localweb

import (
	"context"
	"net/http"
	"strconv"
	"time"
)

// handleMeshRelayProbe serves POST /v1/mesh/relaytest (local-token gated): drive one segment of the relay path and report it.
//
// It is a POST, not a GET, because it SENDS traffic — a few seconds of frames
// over the node's live relay link. That is cheap and safe, but it is an action
// rather than a reading, and the local-token gate that guards the other actions
// should guard it too.
func (s *Server) handleMeshRelayProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.cfg.Mesh == nil {
		writeError(w, http.StatusNotFound, "mesh not configured")
		return
	}
	q := r.URL.Query()
	seconds := clampProbeSeconds(q.Get("seconds"))
	// The context outlives the run by a margin: the probe waits half a second at
	// the end for frames still in flight, and cutting it off there would report
	// them as loss that is not there.
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(seconds+20)*time.Second)
	defer cancel()

	res, err := s.cfg.Mesh.ProbeRelayLeg(ctx, q.Get("relay"),
		atoiOr(q.Get("size"), 1200), atofOr(q.Get("rate"), 0), seconds, q.Get("oneway") == "1")
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// clampProbeSeconds bounds the run so a typo in a query string cannot pin a
// relay link to a measurement for an hour.
func clampProbeSeconds(s string) int {
	n := atoiOr(s, 10)
	if n < 1 {
		n = 1
	}
	if n > 60 {
		n = 60
	}
	return n
}

func atoiOr(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func atofOr(s string, def float64) float64 {
	if s == "" {
		return def
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return def
	}
	return f
}
