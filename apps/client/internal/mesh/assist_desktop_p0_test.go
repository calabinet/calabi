package mesh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"image/jpeg"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

type desktopPipe struct {
	in  io.WriteCloser
	out io.ReadCloser
}

func startDesktopPipe(t *testing.T, exe, role, path string) desktopPipe {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	cmd := exec.CommandContext(ctx, exe, role, path)
	home := t.TempDir()
	local, roaming := filepath.Join(home, "AppData", "Local"), filepath.Join(home, "AppData", "Roaming")
	for _, dir := range []string{local, roaming} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			cancel()
			t.Fatal(err)
		}
	}
	cmd.Env = append(os.Environ(), "HOME="+home, "USERPROFILE="+home, "LOCALAPPDATA="+local, "APPDATA="+roaming)
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		defer cancel()
		in.Close()
		if err := cmd.Wait(); err != nil {
			t.Error(err)
		}
	})
	return desktopPipe{in, out}
}

// Deliver the bytes from the receiving TUN, validating addresses, sequence and
// offsets before reassembly. Stop-and-wait is intentional in this.
func desktopHop(t *testing.T, p *probeBusinessPair, from int, payload []byte, deadline <-chan time.Time) []byte {
	t.Helper()
	to := 1 - from
	packet := assistDatagram(p.addresses[from], p.addresses[to], string(payload))
	select {
	case p.channels[from].Outbound <- packet:
	case <-deadline:
		t.Fatal("send deadline")
	}
	select {
	case got := <-p.channels[to].Inbound:
		if len(got) != len(packet) || !bytes.Equal(got[:28], packet[:28]) {
			t.Fatal("unexpected UDP header")
		}
		return got[28:]
	case <-deadline:
		t.Fatal("receive deadline")
	}
	return nil
}

func TestAssistDesktopStreamP0(t *testing.T) {
	exe := os.Getenv("CALABI_ASSIST_P0_DESKTOP")
	if exe == "" {
		t.Skip("requires local Windows consent")
	}
	for _, path := range []string{PathDirect, PathRelay} {
		t.Run(path, func(t *testing.T) {
			p := assistPair(t, path)
			suffix := ""
			noteRun := os.Getenv("CALABI_ASSIST_P0_INPUT") == "notepad"
			inputRun := os.Getenv("CALABI_ASSIST_P0_INPUT") == "1" || noteRun
			if inputRun {
				suffix = "-input"
			}
			if noteRun {
				suffix = "-note"
			}
			viewer := startDesktopPipe(t, exe, "view"+suffix, path)
			host := startDesktopPipe(t, exe, "send"+suffix, path)
			var runner previewActions
			var frames, fragments, denied uint32
			var first, last time.Time
			var maxGap time.Duration
			var size int
			var width, height int
			distinct := map[[32]byte]bool{}
			bind := p.devices[1].bind
			directStart, relayStart := bind.txDirect.Load(), bind.txRelay.Load()
			for frames < 40 || last.Sub(first) < 8*time.Second || (inputRun && !runner.done) {
				if (frames >= 160 && !inputRun) || frames >= 1200 {
					t.Fatal("stream duration gate")
				}
				// A request is delivered to the host before the host IPC is polled.
				deadline := time.After(5 * time.Second)
				if req := desktopHop(t, p, 0, []byte("next-frame"), deadline); string(req) != "next-frame" {
					t.Fatal("bad request")
				}
				if err := binary.Write(host.in, binary.LittleEndian, uint32(0)); err != nil {
					t.Fatal(err)
				}
				var length uint32
				if err := binary.Read(host.out, binary.LittleEndian, &length); err != nil {
					t.Fatal(err)
				}
				if length == 0 {
					if frames != 0 {
						t.Fatal("sharing stopped")
					}
					if msg := desktopHop(t, p, 1, []byte("denied"), deadline); string(msg) != "denied" {
						t.Fatal("bad denial")
					}
					denied++
					time.Sleep(150 * time.Millisecond)
					continue
				}
				if denied == 0 || length > 2000000 {
					t.Fatal("unexpected first response or frame size")
				}
				src := make([]byte, length)
				if _, err := io.ReadFull(host.out, src); err != nil {
					t.Fatal(err)
				}
				dst := make([]byte, 0, length)
				deadline = time.After(5 * time.Second)
				for offset := 0; offset < len(src); {
					n := len(src) - offset
					if n > 1100 {
						n = 1100
					}
					part := make([]byte, 12+n)
					binary.BigEndian.PutUint32(part, frames+1)
					binary.BigEndian.PutUint32(part[4:], uint32(offset))
					binary.BigEndian.PutUint32(part[8:], length)
					copy(part[12:], src[offset:offset+n])
					got := desktopHop(t, p, 1, part, deadline)
					if binary.BigEndian.Uint32(got) != frames+1 || int(binary.BigEndian.Uint32(got[4:])) != len(dst) || binary.BigEndian.Uint32(got[8:]) != length {
						t.Fatal("unexpected frame fragment")
					}
					dst = append(dst, got[12:]...)
					offset += n
					fragments++
				}
				digest := sha256.Sum256(dst)
				if digest != sha256.Sum256(src) {
					t.Fatal("frame integrity")
				}
				info, err := jpeg.DecodeConfig(bytes.NewReader(dst))
				if err != nil {
					t.Fatal(err)
				}
				width, height = info.Width, info.Height
				if err := binary.Write(viewer.in, binary.LittleEndian, uint32(len(dst))); err != nil {
					t.Fatal(err)
				}
				if _, err := viewer.in.Write(dst); err != nil {
					t.Fatal(err)
				}
				var ack uint32
				if err := binary.Read(viewer.out, binary.LittleEndian, &ack); err != nil {
					t.Fatal(err)
				}
				if ack != frames+1 {
					t.Fatal("receiver did not paint current frame")
				}
				frames++
				size += len(dst)
				distinct[digest] = true
				now := time.Now()
				if last.IsZero() {
					first = now
				} else if gap := now.Sub(last); gap > maxGap {
					maxGap = gap
				}
				last = now
				if inputRun && !runner.done {
					ready := frames >= 40 && last.Sub(first) >= 8*time.Second
					if noteRun {
						runner.noteStep(t, p, host, viewer, ready)
					} else {
						runner.step(t, p, host, viewer, ready)
					}
				}
				time.Sleep(100 * time.Millisecond)
			}
			direct, relay := bind.txDirect.Load()-directStart, bind.txRelay.Load()-relayStart
			t.Logf("painted=%d distinct=%d resolution=%dx%d span=%s max_gap=%s JPEG_bytes=%d fragments=%d denied=%d direct_tx=%d relay_tx=%d", frames, len(distinct), width, height, last.Sub(first), maxGap, size, fragments, denied, direct, relay)
			if len(distinct) < 10 || maxGap > 1500*time.Millisecond || (path == PathDirect && (direct < uint64(fragments) || relay != 0)) || (path == PathRelay && (relay < uint64(fragments) || direct != 0)) {
				t.Fatal("continuity/path check failed")
			}
		})
	}
}
