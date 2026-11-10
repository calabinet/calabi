package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
)

func meshReadFailure(err error) string {
	var network net.Error
	switch {
	case errors.Is(err, filetransfer.ErrCopySessionEnded):
		return "error session"
	case errors.Is(err, filetransfer.ErrCopyOfferUnavailable):
		return "error offer"
	case errors.Is(err, filetransfer.ErrCopySourceRead):
		return "error source"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &network) && network.Timeout():
		return "error timeout"
	default:
		return "error"
	}
}

func (d *desktopFileAgent) meshCopyDiagnostic(stage, detail string) {
	d.mu.RLock()
	ip, _ := netip.ParseAddr(d.view.Overlay)
	d.mu.RUnlock()
	d.recordPeerEvent(ip, "stage="+stage+" reason="+detail, "rdp_copy", "WARN")
}

// Private pipe owned by this logon's Shell adapter. Reads are polled, so a
// slow network request never holds the pipe and prevents cancellation.
func (d *desktopFileAgent) meshPasteRequest(f []string, session string) string {
	d.opMu.Lock()
	w, err := d.ensure()
	d.opMu.Unlock()
	if err != nil {
		if f[0] != "mesh_state" {
			d.meshCopyDiagnostic("workspace", "unavailable")
		}
		return "error"
	}
	var state filetransfer.CopySnapshot
	if session != "" || f[0] == "mesh_state" {
		state = w.Agent.CopySnapshot()
		if session != "" && state.Session != session {
			return "none"
		}
	}
	switch f[0] {
	case "mesh_clear":
		if len(f) == 2 {
			w.Agent.CopyClear(d.ctx, f[1])
			return "ok"
		}
	case "mesh_state":
		s := state
		if s.Session == "" {
			return "none"
		}
		role := 0
		if s.Host {
			role = 1
		}
		offer := s.Offer
		if offer == "" {
			offer = "-"
		}
		return fmt.Sprintf("state %s %d %s %s %s", s.Session, role, s.PeerIP, offer, hex.EncodeToString(s.Manifest))
	case "mesh_offer":
		if len(f) != 3 || len(f[2]) > 16384 {
			return "error"
		}
		b, e := hex.DecodeString(f[2])
		if e != nil || len(b) == 0 || b[len(b)-1] != 0 {
			return "error"
		}
		paths := strings.Split(string(b[:len(b)-1]), "\x00")
		if e := w.Agent.CopyOffer(d.ctx, f[1], paths); e == nil {
			return "ok"
		} else {
			var pathError *os.PathError
			if errors.As(e, &pathError) {
				d.meshCopyDiagnostic("offer", "source_file: "+pathError.Err.Error())
			} else {
				d.meshCopyDiagnostic("offer", e.Error())
			}
		}
	case "mesh_read":
		if len(f) != 5 {
			return "error"
		}
		index, e1 := strconv.Atoi(f[2])
		offset, e2 := strconv.ParseInt(f[3], 10, 64)
		count, e3 := strconv.Atoi(f[4])
		if e1 != nil || e2 != nil || e3 != nil {
			return "error"
		}
		b, pending, e := w.Agent.CopyRead(f[1], index, offset, count)
		if e != nil {
			d.meshCopyDiagnostic("read", e.Error())
			return meshReadFailure(e)
		}
		if pending {
			return "wait"
		}
		return "data " + hex.EncodeToString(b)
	case "mesh_cancel":
		if len(f) == 2 {
			w.Agent.CopyCancel(f[1])
			return "ok"
		}
	}
	return "error"
}
