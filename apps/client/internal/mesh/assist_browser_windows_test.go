//go:build windows && assistintegration

package mesh

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"github.com/calabinet/calabi/apps/client/internal/assistance"
	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"
)

// Only the test driver has this private pipe. The browser binding can submit
// ordinary assistance commands, while the driver owns fault injection and OS observations.
func runAssistBrowser(t *testing.T, script, route string, note assistNote, client *http.Client, target netip.Addr, port uint16, cut *atomic.Bool, agent *filetransfer.Agent) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", script, route, target.String(), t.TempDir())
	cmd.Stderr = os.Stderr
	in, e := cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	out, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() {
		in.Close()
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	enc := json.NewEncoder(in)
	lines := bufio.NewScanner(out)
	var measurement chan string
	var session string
	var controller assistance.Controller
	for lines.Scan() {
		var m struct {
			ID      int
			Kind    string
			Command assistance.Command
		}
		if e = json.Unmarshal(lines.Bytes(), &m); e != nil {
			t.Fatal(e)
		}
		var value any
		var failure error
		switch m.Kind {
		case "wire":
			c := m.Command
			if c.Op == "input" {
				x, y := note.point(t)
				if (c.Input == "down" || c.Input == "move") && (c.X < x-200 || c.X > x+1400 || c.Y < y-200 || c.Y > y+200) {
					t.Fatal("pointer outside dedicated editor")
				}
				if c.Input == "text" {
					if c.Text != "远程" && c.Text != "新词" && c.Text != "旧词" {
						t.Fatal("unexpected test commit")
					}
					fg, _, _ := assistUser.NewProc("GetForegroundWindow").Call()
					if fg != note.hwnd {
						t.Fatal("IME outside dedicated editor")
					}
				}
				if c.Input == "keydown" || c.Input == "keyup" {
					fg, _, _ := assistUser.NewProc("GetForegroundWindow").Call()
					if fg != note.hwnd || (c.X != 55 && c.X != 16) {
						t.Fatal("key outside dedicated editor")
					}
				}
			}
			var r assistance.Reply
			r, failure = controller.Do(ctx, client, target, port, c)
			value = r
			if failure == nil && c.Op == "request" {
				if r.ID == "" || r.ID == session {
					t.Fatal("session ID reused")
				}
				if session != "" {
					if _, err := assistance.Exchange(ctx, client, target, port, assistance.Command{Op: "frame", ID: session}); err == nil {
						t.Fatal("old session survived")
					}
				}
				session = r.ID
			}
		case "editor-focused":
			fg, _, _ := assistUser.NewProc("GetForegroundWindow").Call()
			value = fg == note.hwnd
		case "point":
			x, y := note.point(t)
			value = []int{x, y}
		case "observe":
			sel, _, _ := assistUser.NewProc("SendMessageW").Call(note.edit, 0xb0, 0, 0)
			value = map[string]any{"text": note.text(), "selection": int(sel>>16&65535) - int(sel&65535), "shift": heldAssist(16), "left": heldAssist(1)}
		case "revoke", "cut":
			if !heldAssist(16) || !heldAssist(1) {
				t.Fatal("expected held Shift and left button")
			}
			measurement = make(chan string, 1)
			started := time.Now()
			if m.Kind == "cut" {
				cut.Store(true)
			}
			go observeAssistRelease(ctx, m.Kind, started, measurement)
		case "timing":
			select {
			case v := <-measurement:
				if v == "" {
					t.Fatal("release measurement timed out")
				}
				t.Log(v)
				value = v
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		case "disable-assistance":
			failure = agent.SetAssistance(false)
		case "restore":
			cut.Store(false)
		default:
			t.Fatal("unknown driver command")
		}
		reply := map[string]any{"id": m.ID, "value": value}
		if failure != nil {
			reply["error"] = failure.Error()
		}
		if e := enc.Encode(reply); e != nil {
			t.Fatal(e)
		}
	}
	if e := lines.Err(); e != nil {
		t.Fatal(e)
	}
	if e := cmd.Wait(); e != nil {
		t.Fatal(e)
	}
}

func observeAssistRelease(ctx context.Context, mode string, start time.Time, out chan<- string) {
	previous := start
	if mode == "revoke" {
		for !heldAssist(0x77) {
			if time.Since(start) > 110*time.Second || ctx.Err() != nil {
				out <- ""
				return
			}
			previous = time.Now()
			time.Sleep(time.Millisecond)
		}
		start = previous // upper bound from the last sample before down
	}
	var shift, left time.Duration
	for time.Since(start) < 8*time.Second && ctx.Err() == nil {
		now := time.Since(start)
		if shift == 0 && !heldAssist(16) {
			shift = now
		}
		if left == 0 && !heldAssist(1) {
			left = now
		}
		if shift > 0 && left > 0 {
			out <- fmt.Sprintf("%s: Shift=%s left=%s", mode, shift, left)
			return
		}
		time.Sleep(time.Millisecond)
	}
	out <- ""
}
