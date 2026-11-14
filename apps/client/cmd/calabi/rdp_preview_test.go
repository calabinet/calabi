package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/calabinet/calabi/apps/client/internal/filecontrol"
	"image/png"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestRDPPreviewFitsAgentPipe(t *testing.T) {
	var input, output bytes.Buffer
	encoded := strings.Repeat("00", 2+192*108*4)
	writer := json.NewEncoder(&input)
	_ = writer.Encode(fileAction{Action: "rdp_preview", RDPPreview: encoded})
	_ = writer.Encode(fileAction{Action: "snapshot"})
	_ = writer.Encode(fileAction{Action: "rdp_record", RDPName: encoded})
	var called []string
	if serveFileActions(&input, &output, func(a fileAction) (any, error) {
		called = append(called, a.Action)
		return map[string]bool{"ok": true}, nil
	}) != 0 {
		t.Fatal("preview exceeded pipe limit")
	}
	if strings.Join(called, ",") != "rdp_preview,snapshot" {
		t.Fatalf("unexpected actions %v", called)
	}
}

func TestRDPPreviewRechecksAuthorization(t *testing.T) {
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
		t.Skip("desktop RDP")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var lock sync.Mutex
	view := filecontrol.Snapshot{Ready: true, AccountID: 1, Scope: "org", Overlay: "100.64.0.1", Members: []filecontrol.Member{{DeviceKey: "peer", IP: "100.64.0.2", OwnWindows: true}}}
	profile := rdpProfile(view)
	ctl := &filecontrol.Control{Source: filecontrol.Source{View: func() (filecontrol.Snapshot, error) { lock.Lock(); defer lock.Unlock(); return view, nil }}}
	console := fmt.Sprintf("http://127.0.0.1:%d", 20000+os.Getpid()%10000)
	done, err := filecontrol.Serve(ctx, ctl, console)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); <-done }()
	d := &desktopFileAgent{ctx: ctx, console: console, dir: t.TempDir()}
	preview := fileAction{Action: "rdp_preview", Peer: "peer", RDPProfile: profile, RDPPreview: "0101ff0000ff"}
	if _, err := d.rdpProfileAction(preview); err == nil {
		t.Fatal("created preview before a successful login record")
	}
	if _, err := d.rdpProfileAction(fileAction{Action: "rdp_record", Peer: "peer", RDPProfile: profile, RDPAccount: "user"}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.rdpProfileAction(preview); err != nil {
		t.Fatal(err)
	}
	history, err := d.rdpProfileAction(fileAction{Action: "rdp_history"})
	if err != nil || len(history.([]remoteRecent)) != 1 || history.([]remoteRecent)[0].Thumbnail == "" {
		t.Fatalf("history lost preview: %v", err)
	}
	for _, change := range []func(){func() { view.Scope = "other" }, func() { view.AccountID = 2 }, func() { view.Ready = false }, func() { view.Members = nil }} {
		lock.Lock()
		saved := view
		change()
		lock.Unlock()
		_, err := d.rdpProfileAction(preview)
		if err == nil {
			t.Fatal("stored preview under stale authorization")
		}
		lock.Lock()
		view = saved
		lock.Unlock()
	}
}

func TestRDPPreviewRoundTripAndIsolation(t *testing.T) {
	dir := t.TempDir()
	// Distinct red/green pixels detect channel and row order mistakes.
	raw := []byte{2, 1, 255, 0, 0, 255, 0, 255, 0, 255}
	if err := writeRDPPreview(dir, "account/org", "device", hex.EncodeToString(raw)); err != nil {
		t.Fatal(err)
	}
	preview := readRDPPreview(dir, "account/org", "device")
	data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(preview, "data:image/png;base64,"))
	if err != nil {
		t.Fatal(err)
	}
	image, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	r, g, _, _ := image.At(0, 0).RGBA()
	if r != 65535 || g != 0 {
		t.Fatal("red pixel changed")
	}
	r, g, _, _ = image.At(1, 0).RGBA()
	if r != 0 || g != 65535 {
		t.Fatal("green pixel changed")
	}
	if readRDPPreview(dir, "other/org", "device") != "" || readRDPPreview(dir, "account/org", "other") != "" {
		t.Fatal("preview crossed identity boundary")
	}
	for _, invalid := range []string{"", "zzzzzzzzzzzz", "0000ffffffff", hex.EncodeToString([]byte{193, 1, 0, 0, 0, 255}), strings.Repeat("a", 200000)} {
		if writeRDPPreview(dir, "account/org", "device", invalid) == nil {
			t.Fatal("accepted invalid preview")
		}
		if readRDPPreview(dir, "account/org", "device") != preview {
			t.Fatal("invalid data replaced previous preview")
		}
	}
	if err := os.WriteFile(filepath.Join(dir, rdpPreviewName("account/org", "device")), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if readRDPPreview(dir, "account/org", "device") != "" {
		t.Fatal("returned corrupt preview")
	}
}
