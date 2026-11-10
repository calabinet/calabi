package mesh

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Negative IPC opcode multiplexes local input/status onto the existing frame pipe.
func inputIPC(t *testing.T, proc desktopPipe, msg string) string {
	t.Helper()
	buf := make([]byte, 8+len(msg))
	binary.LittleEndian.PutUint32(buf, 0xffffffff)
	binary.LittleEndian.PutUint32(buf[4:], uint32(len(msg)))
	copy(buf[8:], msg)
	if _, err := proc.in.Write(buf); err != nil {
		t.Fatal(err)
	}
	var n uint32
	if err := binary.Read(proc.out, binary.LittleEndian, &n); err != nil {
		t.Fatal(err)
	}
	if n > 16384 {
		t.Fatal("oversized input reply")
	}
	reply := make([]byte, n)
	if _, err := io.ReadFull(proc.out, reply); err != nil {
		t.Fatal(err)
	}
	return string(reply)
}

type previewActions struct {
	stage        int
	old          string
	done         bool
	noteSnapshot string
	noteEvents   []string
}

// Compare independent observations from Notepad's own Edit HWND, including
// selection indices. A denial response on its own doesn't prove the app was unchanged.
func (a *previewActions) noteStep(t *testing.T, p *probeBusinessPair, host, viewer desktopPipe, ready bool) {
	t.Helper()
	remote := func(msg string) string {
		timer := time.After(3 * time.Second)
		got := desktopHop(t, p, 0, []byte(msg), timer)
		return string(desktopHop(t, p, 1, []byte(inputIPC(t, host, string(got))), timer))
	}
	stats := func(local bool) []string {
		var raw string
		if local {
			raw = inputIPC(t, host, "inspect-note")
		} else {
			raw = remote("note")
		}
		f := strings.Fields(raw)
		if len(f) != 12 {
			t.Fatalf("unexpected note status field count: %d", len(f))
		}
		b, err := base64.StdEncoding.DecodeString(f[5])
		if err != nil {
			t.Fatal(err)
		}
		f[5] = string(b)
		return f
	}
	f := stats(false)
	snapshot := func(f []string) string { return strings.Join(f[5:8], "/") }
	grant := "0"
	if f[1] == "1" {
		grant = f[0]
	}
	batch := inputIPC(t, viewer, "grant "+grant)
	if batch != "" {
		for _, event := range strings.Split(batch, ";") {
			remote(event)
		}
	}
	run := func(action, want string) []string {
		events := strings.Split(inputIPC(t, viewer, action), ";")
		expected := map[string]int{"click": 2, "text": 4, "select": 3}[strings.Fields(action)[0]]
		if len(events) != expected {
			t.Fatalf("unexpected viewer events for %s: %d", action, len(events))
		}
		for _, e := range events {
			if got := remote(e); got != want {
				t.Fatalf("notepad %s: %q expected %q", e, got, want)
			}
			if strings.HasPrefix(action, "select ") && want == "ok" && !strings.Contains(e, " up ") {
				until := time.Now().Add(500 * time.Millisecond)
				end := "7"
				if strings.Contains(e, " move ") {
					end = "11"
				}
				for {
					current := stats(false)
					if current[6] == "7" && current[7] == end {
						break
					}
					if time.Now().After(until) {
						t.Fatalf("drag event %s: actual selection %v", e, current[6:8])
					}
					time.Sleep(8 * time.Millisecond)
				}
			}
		}
		return events
	}
	verify := func(start, end int, text string) {
		until := time.Now().Add(500 * time.Millisecond)
		for {
			f = stats(false)
			if f[5] == text && f[6] == strconv.Itoa(start) && f[7] == strconv.Itoa(end) {
				return
			}
			if time.Now().After(until) {
				t.Fatalf("Notepad readback mismatch, textMatches=%v sel=%v want %d..%d", f[5] == text, f[6:8], start, end)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	const seed = "CALABI-0123456789-TEST"
	const edited = "CALABI-远程中文0123456789-TEST"
	replay := func() {
		for _, event := range a.noteEvents {
			if remote(event) != "denied" {
				t.Fatal("stale Notepad input accepted")
			}
		}
		time.Sleep(120 * time.Millisecond)
		if snapshot(stats(true)) != a.noteSnapshot {
			t.Fatal("Notepad changed after stale input")
		}
	}
	switch a.stage {
	case 0:
		if f[5] != seed {
			t.Fatal("wrong test document")
		}
		before := snapshot(f)
		run("click "+strings.Join(f[8:10], " "), "denied")
		run("text", "denied")
		run("select "+strings.Join(f[8:12], " "), "denied")
		if snapshot(stats(true)) != before {
			t.Fatal("view-only input changed Notepad")
		}
		a.stage++
	case 1:
		if grant == "0" {
			return
		}
		a.noteEvents = run("click "+strings.Join(f[8:10], " "), "ok")
		verify(7, 7, seed)
		a.noteEvents = append(a.noteEvents, run("text", "ok")...)
		verify(11, 11, edited)
		for remote("separate-click") != "ready" {
			stats(false)
			time.Sleep(15 * time.Millisecond)
		}
		a.noteEvents = append(a.noteEvents, run("select "+strings.Join(f[8:12], " "), "ok")...)
		verify(7, 11, edited)
		a.noteSnapshot = snapshot(f)
		a.stage++
		t.Log("Notepad confirmed caret 7, Unicode insertion, selection [7,11)")
	case 2:
		if f[2] != "revoke" {
			return
		}
		replay()
		a.stage++
		t.Log("revoked: all nine delayed inputs rejected; document and selection unchanged")
	case 3:
		if grant == "0" || !ready {
			return
		}
		replay() // previous grant remains invalid even though a new one is active
		for i, e := range a.noteEvents {
			_, tail, _ := strings.Cut(e, " ")
			a.noteEvents[i] = grant + " " + tail
		}
		stats(false) // start the silence at an acknowledged heartbeat
		start := time.Now()
		for time.Since(start) < 2*time.Second {
			if stats(true)[2] == "timeout" {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		elapsed := time.Since(start)
		if stats(true)[2] != "timeout" {
			t.Fatal("missing Notepad disconnect")
		}
		replay()
		t.Logf("silent disconnect detected after %s; nine events with last active grant rejected, Notepad unchanged", elapsed)
		a.done = true
	}
}

func (a *previewActions) step(t *testing.T, p *probeBusinessPair, host, viewer desktopPipe, canDisconnect bool) {
	t.Helper()
	remote := func(msg string) string {
		deadline := time.After(3 * time.Second)
		request := desktopHop(t, p, 0, []byte(msg), deadline)
		return string(desktopHop(t, p, 1, []byte(inputIPC(t, host, string(request))), deadline))
	}
	parse := func(msg string) []string {
		f := strings.Fields(msg)
		if len(f) != 12 {
			t.Fatalf("unexpected input stats %q", msg)
		}
		return f
	}
	f := parse(remote("status"))
	grant := "0"
	if f[1] == "1" {
		grant = f[0]
	}
	batch := inputIPC(t, viewer, "grant "+grant)
	// Poll events captured on the viewer while its preview is playing.
	if batch != "" {
		for _, msg := range strings.Split(batch, ";") {
			remote(msg)
		}
	}
	exercise := func(want string) {
		events := strings.Split(inputIPC(t, viewer, fmt.Sprintf("exercise %s %s", f[10], f[11])), ";")
		if len(events) != 10 {
			t.Fatalf("viewer generated %d events: %q", len(events), events)
		}
		for _, msg := range events {
			if got := remote(msg); got != want {
				t.Fatalf("%s: got %s want %s", msg, got, want)
			}
		}
		a.old = events[0]
	}
	switch a.stage {
	case 0:
		exercise("denied")
		f = parse(remote("status"))
		if f[3] != "0" || f[4] != "0" || f[5] != "0" || f[6] != "0" || f[7] != "-" {
			t.Fatalf("view-only changed target: %v", f)
		}
		a.stage++
	case 1, 3:
		if f[1] != "1" || (a.stage == 3 && !canDisconnect) {
			return
		}
		if a.stage == 3 && remote(a.old) != "denied" {
			t.Fatal("old grant reused")
		}
		exercise("ok")
		f = parse(remote("status"))
		first := a.stage == 1
		if f[6] != "1" || (first && (f[3] != "2" || f[4] != "1" || f[5] != "1" || f[7] != "Calabi")) ||
			(!first && (f[3] != "4" || f[4] != "2" || f[5] != "3" || f[7] != "CalabiCalabi")) {
			t.Fatalf("target did not receive click, text and held drag: %v", f)
		}
		if first {
			t.Log("target received click, Calabi and held drag; waiting for local revoke")
			a.stage++
			return
		}
		// Blackhole all session traffic (including heartbeats). Inspect via the
		// harness pipe only. This local observation never refreshes the lease.
		start := time.Now()
		for time.Since(start) < 2*time.Second {
			f = parse(inputIPC(t, host, "inspect"))
			if f[8] == "timeout" {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if f[8] != "timeout" || f[6] != "0" || f[5] != "4" || remote(a.old) != "denied" {
			t.Fatalf("disconnect allowed stuck/late input: %v", f)
		}
		t.Logf("silent link: detected and released after %v, target release %s us", time.Since(start), f[9])
		a.done = true
	case 2:
		if f[8] != "revoke" {
			return
		}
		if f[6] != "0" || f[5] != "2" || remote(a.old) != "denied" {
			t.Fatalf("revoked drag not released: %v", f)
		}
		if _, err := strconv.Atoi(f[9]); err != nil {
			t.Fatal(err)
		}
		t.Logf("local revoke: held drag released in %s us; old grant denied", f[9])
		a.stage++
	}
}
