package assistance

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Command is shared by the desktop bridge and the pinned mesh endpoint.
// Only the local host window can grant or revoke a permission.
type Command struct {
	Wheel    int    `json:"wheel,omitempty"`
	Baseline int    `json:"baseline,omitempty"`
	Op       string `json:"op"`
	ID       string `json:"id,omitempty"`
	Epoch    int    `json:"epoch,omitempty"`
	Input    string `json:"input,omitempty"`
	Text     string `json:"text,omitempty"`
	Seq      uint32 `json:"seq,omitempty"`
	X        int    `json:"x,omitempty"`
	Y        int    `json:"y,omitempty"`
}
type Reply struct {
	ViewPing        bool   `json:"view_ping,omitempty"`
	LocalSplitFrame bool   `json:"local_split_frame,omitempty"`
	FramePending    bool   `json:"frame_pending,omitempty"`
	FrameDelta      bool   `json:"frame_delta,omitempty"`
	Revision        int    `json:"revision,omitempty"`
	Patch           string `json:"patch,omitempty"`
	X               int    `json:"x,omitempty"`
	Y               int    `json:"y,omitempty"`
	ID              string `json:"id,omitempty"`
	State           string `json:"state"`
	Epoch           int    `json:"epoch,omitempty"`
	Frame           string `json:"frame,omitempty"`
	Applied         bool   `json:"applied,omitempty"`
	TextInput       bool   `json:"text_input,omitempty"`
	PunctuationKeys bool   `json:"punctuation_keys,omitempty"`
}
type window interface {
	call(Command) (Reply, error)
	done() <-chan struct{}
	close()
}
type Host struct {
	OnWindowExit                func(string, string)
	reportOutcome               bool
	lastID, lastPeer, lastState string
	mu                          sync.Mutex
	open                        func(context.Context, string) (window, error)
	peer, id                    string
	activeCtx                   context.Context
	active                      window
}

func NewHost() *Host { return &Host{open: openWindow} }
func (h *Host) Serve(ctx context.Context, peer, label string, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost || r.URL.Path != "/assist/v1/session" {
		http.NotFound(w, r)
		return
	}
	var c Command
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
	dec.DisallowUnknownFields()
	if dec.Decode(&c) != nil || dec.Decode(&struct{}{}) != io.EOF {
		http.Error(w, "invalid command", 400)
		return
	}
	reply, err := h.exchange(ctx, peer, label, c)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(reply)
}

// Remember one completed session so a concurrent pulse cannot consume its outcome.
func (h *Host) finishWindow() {
	if h.reportOutcome {
		if w, ok := h.active.(interface{ outcome() string }); ok {
			if state := w.outcome(); state != "" {
				h.lastID, h.lastPeer, h.lastState = h.id, h.peer, state
			}
		}
	}
	h.active = nil
}
func (h *Host) exchange(ctx context.Context, peer, label string, c Command) (Reply, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.active != nil {
		select {
		case <-h.active.done():
			h.finishWindow()
		default:
		}
	}
	if ctx.Err() != nil {
		return Reply{}, ctx.Err()
	}
	if c.Op == "request" {
		if h.active != nil {
			return Reply{}, errors.New("another assistance request is active")
		}
		if ctx.Err() != nil || peer == "" {
			return Reply{}, errors.New("assistance unavailable")
		}
		win, err := h.open(ctx, label)
		if err != nil {
			return Reply{}, err
		}
		h.activeCtx = ctx
		h.active = win
		h.reportOutcome = c.Input == "outcome-v1"
		h.id = rand.Text()
		h.peer = peer
		if logExit := h.OnWindowExit; logExit != nil {
			go func() {
				<-win.done()
				reason := "helper_exit"
				if w, ok := win.(interface{ outcome() string }); ok && w.outcome() != "" {
					reason = w.outcome()
				}
				logExit(peer, reason)
			}()
		}
		return Reply{State: "pending", ID: h.id, FrameDelta: true, ViewPing: true}, nil
	}
	if c.ID != "" && c.ID == h.lastID && peer == h.lastPeer {
		return h.windowOutcome()
	}
	if h.active == nil || h.activeCtx.Err() != nil || c.ID == "" || h.peer != peer || h.id != c.ID {
		return Reply{}, errors.New("assistance session ended")
	}
	switch c.Op {
	case "end":
		h.active.close()
		select {
		case <-h.active.done():
			h.active = nil
		case <-time.After(2 * time.Second):
			return Reply{}, errors.New("assistance window is closing")
		}
		return Reply{State: "ended"}, nil
	case "frame", "frame_delta", "input", "release", "pulse", "view_ping":
	default:
		return Reply{}, errors.New("unknown assistance operation")
	}
	if strings.ContainsAny(c.Input, " \r\n\t") || len(c.Input) > 20 {
		return Reply{}, errors.New("invalid input")
	}
	reply, err := h.active.call(c)
	if err != nil && h.reportOutcome {
		select {
		case <-h.active.done():
			h.finishWindow()
			if c.ID == h.lastID && peer == h.lastPeer {
				return h.windowOutcome()
			}
		case <-time.After(2 * time.Second):
		}
	}
	reply.TextInput = err == nil && reply.State == "control"
	reply.PunctuationKeys = reply.TextInput
	return reply, err
}

func (h *Host) windowOutcome() (Reply, error) {
	if h.lastState == "declined" || h.lastState == "stopped" {
		return Reply{State: h.lastState}, nil
	}
	return Reply{}, errors.New(h.lastState)
}
