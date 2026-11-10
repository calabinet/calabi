package assistance

import (
	"context"
	"errors"
	"testing"
)

type outcomeWindow struct {
	stopped chan struct{}
	reason  string
}

func (w *outcomeWindow) done() <-chan struct{} { return w.stopped }
func (w *outcomeWindow) close()                { close(w.stopped) }
func (w *outcomeWindow) outcome() string       { return w.reason }
func (w *outcomeWindow) call(Command) (Reply, error) {
	w.close()
	return Reply{}, errors.New("pipe closed")
}

func TestConsentWindowOutcome(t *testing.T) {
	for _, reason := range []string{"declined", "stopped", ""} {
		for _, alreadyClosed := range []bool{true, false} {
			w := &outcomeWindow{make(chan struct{}), reason}
			h := &Host{open: func(context.Context, string) (window, error) { return w, nil }}
			ctx := context.Background()
			req, err := h.exchange(ctx, "owner", "Windows", Command{Op: "request", Input: "outcome-v1"})
			if err != nil {
				t.Fatal(err)
			}
			if alreadyClosed {
				w.close()
			}
			for _, op := range []string{"pulse", "frame_delta", "input", "end"} {
				got, err := h.exchange(ctx, "owner", "Windows", Command{Op: op, ID: req.ID})
				if reason == "" {
					if err == nil {
						t.Fatal("unexpected exit treated as manual")
					}
				} else if err != nil || got.State != reason || got.Applied || got.Frame != "" {
					t.Fatalf("%s: %+v %v", op, got, err)
				}
			}
			if _, err := h.exchange(ctx, "other", "Windows", Command{Op: "frame", ID: req.ID}); err == nil {
				t.Fatal("outcome leaked to another peer")
			}
		}
	}
}
