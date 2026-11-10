package filetransfer

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestShellPasteNativeStreamOverTLS(t *testing.T) {
	exe := os.Getenv("CALABI_SHELL_PASTE_TEST_EXE")
	if exe == "" {
		t.Skip("native paste bridge fixture not supplied")
	}
	for _, mode := range []string{"complete", "cancel", "clipboard"} {
		t.Run(mode, func(t *testing.T) {
			data := make([]byte, 4<<20)
			for i := range data {
				data[i] = byte(i % 251)
			}
			w, r, a, _ := shellPair(t, data)
			p, err := a.NewShellPaste(context.Background(), t.TempDir(), "source", r.List()[0].Batch)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, exe, "--bridge-test", "source/"+r.List()[0].Batch, mode)
			if mode == "clipboard" {
				cmd = exec.CommandContext(ctx, exe, "--clipboard-contract-test", "source/"+r.List()[0].Batch)
			}
			in, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer in.Close()
			out, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer out.Close()
			cmd.Stderr = os.Stderr
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			resolveAttempts := 0
			scanner := bufio.NewScanner(out)
			for scanner.Scan() {
				fields := strings.Fields(scanner.Text())
				if len(fields) < 2 {
					t.Fatal("malformed native request")
				}
				answer := "error"
				switch fields[0] {
				case "resolve":
					resolveAttempts++
					if mode == "clipboard" && resolveAttempts == 1 {
						break
					} // Metadata not ready on the first request.
					answer = "data " + hex.EncodeToString(p.Manifest())
				case "begin":
					if p.Begin() == nil {
						answer = "ok"
					}
				case "status":
					index, _ := strconv.Atoi(fields[2])
					ready, done, total, e := p.Status(index)
					if e == nil {
						state := "wait"
						if ready {
							state = "ready"
						}
						answer = fmt.Sprintf("%s %d %d", state, done, total)
					}
				case "read":
					index, _ := strconv.Atoi(fields[2])
					offset, _ := strconv.ParseInt(fields[3], 10, 64)
					count, _ := strconv.Atoi(fields[4])
					b, e := p.Read(index, offset, count)
					if e == nil {
						answer = "data " + hex.EncodeToString(b)
					}
				case "cancel":
					p.Cancel()
					answer = "ok"
				case "release":
					p.Close()
					answer = "ok"
				}
				if _, err = fmt.Fprintln(in, answer); err != nil {
					break
				}
			}
			if err = cmd.Wait(); err != nil {
				t.Fatal("native bridge failed", err)
			}
			if mode == "cancel" {
				syncUntil(t, func() bool { return w.Jobs()[0].State == "cancelled" })
				if r.List()[0].State != "cancelled" {
					t.Fatal("native cancellation not reflected in receiver")
				}
			}
		})
	}
}
