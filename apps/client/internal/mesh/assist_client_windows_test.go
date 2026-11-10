//go:build windows && assistintegration

package mesh

import (
	"bytes"
	"context"
	"encoding/base64"
	"image/jpeg"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/calabinet/calabi/apps/client/internal/assistance"
	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func assistClientNetwork(t *testing.T, route string, cut *atomic.Bool, shape *[2]leasePath, weakLease bool) (*probeBusinessPair, [2]*netstack.Net) {
	t.Helper()
	drainDone := make(chan struct{})
	t.Cleanup(func() { close(drainDone) })
	p := assistPair(t, route)
	var nets [2]*netstack.Net
	for i := range nets {
		dev, n, err := netstack.CreateNetTUN([]netip.Addr{p.addresses[i]}, nil, 1280)
		if err != nil {
			t.Fatal(err)
		}
		nets[i] = n
		ctx, cancel := context.WithCancel(context.Background())
		inboundDone := make(chan struct{})
		ch := p.channels[i]
		t.Cleanup(func() {
			cancel()
			<-inboundDone
			// WG stops its peers before closing ChannelTUN. Let a final
			// peer write finish even after its netstack has shut down.
			go func() {
				for {
					select {
					case <-ch.Inbound:
					case <-drainDone:
						return
					}
				}
			}()
			dev.Close()
		})
		forward := ch.Outbound
		if weakLease {
			forward = shape[i].pipe(ctx, forward, cut, i)
		}
		go func() {
			buf := make([]byte, 2000)
			sizes := []int{0}
			for {
				if _, e := dev.Read([][]byte{buf}, sizes, 0); e != nil {
					return
				}
				if cut.Load() || ctx.Err() != nil {
					continue
				}
				packet := append([]byte(nil), buf[:sizes[0]]...)
				select {
				case forward <- packet:
				case <-ctx.Done():
					// Keep draining netstack notifications until dev.Close finishes.
				}
			}
		}()
		go func() {
			defer close(inboundDone)
			for {
				select {
				case packet := <-ch.Inbound:
					if cut.Load() {
						continue
					}
					if _, e := dev.Write([][]byte{packet}, 0); e != nil {
						return
					}
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	return p, nets
}

func TestAssistClientNetworkShutdown(t *testing.T) {
	for _, route := range []string{PathDirect, PathRelay} {
		t.Run(route, func(t *testing.T) {
			var cut atomic.Bool
			var shape [2]leasePath
			p, nets := assistClientNetwork(t, route, &cut, &shape, false)
			dest := netip.AddrPortFrom(p.addresses[1], 17401)
			ln, err := nets[1].ListenTCPAddrPort(dest)
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			client, err := nets[0].DialContext(ctx, "tcp", dest.String())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			server, err := ln.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			// Close a busy connection with data still in flight.
			server.SetWriteDeadline(time.Now().Add(time.Second))
			if _, err := server.Write(make([]byte, 32*1024)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestClientAssistConsent(t *testing.T) {
	if os.Getenv("CALABI_ASSIST_ACCEPTANCE") != "1" {
		t.Skip("requires local desktop consent")
	}
	for _, route := range []string{PathDirect, PathRelay} {
		t.Run(route, func(t *testing.T) {
			home := t.TempDir()
			fileEcho := os.Getenv("CALABI_ASSIST_FILE_ECHO") == "1"
			if fileEcho && route != PathRelay {
				t.Skip("file contention comparison uses the relay")
			}
			for _, key := range []string{"APPDATA", "LOCALAPPDATA", "HOME", "USERPROFILE"} {
				t.Setenv(key, home)
			}
			var cut atomic.Bool
			var shape [2]leasePath
			weakLease := os.Getenv("CALABI_ASSIST_LEASE") == "1"
			p, nets := assistClientNetwork(t, route, &cut, &shape, weakLease || fileEcho)
			src, e := filetransfer.NewIdentity()
			if e != nil {
				t.Fatal(e)
			}
			dst, e := filetransfer.NewIdentity()
			if e != nil {
				t.Fatal(e)
			}
			host := assistance.NewHost()
			source := filetransfer.Peer{IP: p.addresses[0], Fingerprint: src.Fingerprint}
			target := filetransfer.Peer{IP: p.addresses[1], Fingerprint: dst.Fingerprint}
			const port = 17401
			agent, e := filetransfer.NewAgent(filetransfer.AgentConfig{Scope: "isolated", Directory: t.TempDir(), Identity: dst, LocalIP: target.IP, Port: port, Kbps: 4096, MaxBytes: 1024, Authority: func() bool { return true }, Resolve: func(ip netip.Addr) (filetransfer.Grant, bool) {
				return filetransfer.Grant{DeviceKey: "isolated-requester", Peer: source, Port: port}, ip == source.IP
			}, Incoming: func(ip netip.Addr, pt uint16) bool { return ip == source.IP && pt == port }, Assist: func(ctx context.Context, g filetransfer.Grant, w http.ResponseWriter, r *http.Request) {
				host.Serve(ctx, g.DeviceKey, "Calabi 验收 · "+route+" · "+g.Peer.IP.String(), w, r)
			}})
			if e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() { agent.Close() })
			if e = agent.SetAssistance(true); e != nil {
				t.Fatal(e)
			}
			ln, e := nets[1].ListenTCPAddrPort(netip.AddrPortFrom(target.IP, port))
			if e != nil {
				t.Fatal(e)
			}
			if _, e = agent.Serve(ln); e != nil {
				t.Fatal(e)
			}
			tr := &http.Transport{DialContext: nets[0].DialContext, TLSClientConfig: src.ClientTLS(target), IdleConnTimeout: 2 * time.Second}
			client := &http.Client{Transport: tr, Timeout: 18 * time.Second}
			var controller assistance.Controller
			id := ""
			epoch := 0
			call := func(op, input string, x, y int) assistance.Reply {
				t.Helper()
				out, err := controller.Do(context.Background(), client, target.IP, port, assistance.Command{Op: op, ID: id, Epoch: epoch, Input: input, X: x, Y: y})
				if err != nil {
					t.Fatal(err)
				}
				return out
			}
			if os.Getenv("CALABI_ASSIST_VIEW_SLOW") == "1" {
				trace := &echoPulseTrace{base: tr, tracing: true, holdDuration: 4200 * time.Millisecond}
				client.Transport = trace
				reply := call("request", "outcome-v1", 0, 0)
				id = reply.ID
				if id == "" || !reply.ViewPing {
					t.Fatal("missing session or view heartbeat")
				}
				t.Log("Window ready: click 同意查看桌面 only")
				for deadline := time.Now().Add(32 * time.Second); ; {
					if call("release", "", 0, 0).State == "view" {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("consent timeout")
					}
					time.Sleep(150 * time.Millisecond)
				}
				trace.hold.Store(true)
				start := time.Now()
				frame := call("frame_delta", "", 0, 0)
				data, err := base64.StdEncoding.DecodeString(frame.Frame)
				if err != nil || frame.State != "view" {
					t.Fatal("missing view frame")
				}
				img, err := jpeg.Decode(bytes.NewReader(data))
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("first frame %v in %v", img.Bounds().Size(), time.Since(start))
				if call("frame_delta", "", 0, 0).State != "view" {
					t.Fatal("view did not survive delayed response")
				}
				cut.Store(true)
				time.Sleep(5 * time.Second)
				cut.Store(false)
				_, err = controller.Do(context.Background(), client, target.IP, port, assistance.Command{Op: "frame", ID: id})
				if err == nil || !strings.Contains(err.Error(), "viewer_idle_timeout") {
					t.Fatalf("unexpected outcome after disconnect: %v", err)
				}
				t.Log(err)
				return
			}
			note := openAssistNote(t)
			bind := p.devices[1].bind
			direct, relay := bind.txDirect.Load(), bind.txRelay.Load()
			if os.Getenv("CALABI_ASSIST_SPLIT") == "1" {
				checkIndependentReceivers(t, agent, client, "https://"+netip.AddrPortFrom(target.IP, port).String())
			}
			if fileEcho {
				testFileEcho(t, note, client, p, nets, src, dst, &cut)
				if bind.txRelay.Load() <= relay || bind.txDirect.Load() != direct {
					t.Fatal("expected relay-only traffic")
				}
				t.Logf("direct_tx=0 relay_tx=%d", bind.txRelay.Load()-relay)
				return
			}
			if weakLease {
				testWeakLease(t, route, note, client, target.IP, port, &cut, &shape)
				d, r := bind.txDirect.Load()-direct, bind.txRelay.Load()-relay
				if route == PathDirect && (d == 0 || r != 0) || route == PathRelay && (r == 0 || d != 0) {
					t.Fatal("unexpected weak lease path", d, r)
				}
				t.Logf("weak lease direct_tx=%d relay_tx=%d", d, r)
				return
			}
			if script := os.Getenv("CALABI_ASSIST_BROWSER"); script != "" {
				runAssistBrowser(t, script, route, note, client, target.IP, port, &cut, agent)
				d, r := bind.txDirect.Load()-direct, bind.txRelay.Load()-relay
				if route == PathDirect && (d == 0 || r != 0) || route == PathRelay && (r == 0 || d != 0) {
					t.Fatal("unexpected browser path", d, r)
				}
				t.Logf("browser path: direct_tx=%d relay_tx=%d", d, r)
				return
			}
			req := call("request", "", 0, 0)
			id = req.ID
			if id == "" {
				t.Fatal("no session id")
			}
			if s := call("frame", "", 0, 0); s.State != "pending" || s.Frame != "" {
				t.Fatal("expected pending, no desktop")
			}
			if call("input", "keydown", 16, 0).Applied {
				t.Fatal("unapproved input accepted")
			}
			t.Log("pending verified; click 同意查看桌面, wait for control instruction")
			wait := func(state string) assistance.Reply {
				t.Helper()
				for until := time.Now().Add(35 * time.Second); time.Now().Before(until); {
					s := call("frame", "", 0, 0)
					if s.State == state {
						return s
					}
					time.Sleep(70 * time.Millisecond)
				}
				t.Fatal("local authorization timeout for ", state)
				return assistance.Reply{}
			}
			view := wait("view")
			img, e := base64.StdEncoding.DecodeString(view.Frame)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = jpeg.Decode(bytes.NewReader(img)); e != nil {
				t.Fatal("no visible desktop", e)
			}
			if call("input", "keydown", 16, 0).Applied {
				t.Fatal("view-only key accepted")
			}
			t.Log("JPEG and view-only denial verified; click 允许控制")
			grant := wait("control")
			epoch = grant.Epoch
			x, y := note.point(t)
			if !call("input", "down", x, y).Applied || !call("input", "up", 0, 0).Applied {
				t.Fatal("test editor click failed")
			}
			fg, _, _ := assistUser.NewProc("GetForegroundWindow").Call()
			if fg != note.hwnd {
				t.Fatal("dedicated editor did not receive focus after click")
			}
			oldText := note.text()
			if !call("input", "keydown", 55, 0).Applied || !call("input", "keyup", 55, 0).Applied {
				t.Fatal("typing failed")
			}
			time.Sleep(80 * time.Millisecond)
			if strings.Count(note.text(), "7") != strings.Count(oldText, "7")+1 {
				t.Fatal("new character missing in test note")
			}
			if !call("input", "keydown", 16, 0).Applied || !call("input", "down", x, y).Applied || !call("input", "move", x+1000, y).Applied {
				t.Fatal("hold failed")
			}
			if !heldAssist(16) || !heldAssist(1) {
				t.Fatal("Windows did not receive held input")
			}
			t.Log("Shift and left button verified down; press F8 now (remote Shift is held)")
			wait("view")
			if heldAssist(16) || heldAssist(1) {
				t.Fatal("Windows key/button remained down after revoke")
			}
			before := note.text()
			if call("input", "keydown", 66, 0).Applied || call("input", "down", x, y).Applied || note.text() != before {
				t.Fatal("stale input after revoke")
			}
			old := id
			call("end", "", 0, 0)
			req = call("request", "", 0, 0)
			id = req.ID
			fresh := call("frame", "", 0, 0)
			if id == old || fresh.State != "pending" || fresh.Frame != "" {
				t.Fatal("new request inherited permission")
			}
			if _, err := assistance.Exchange(context.Background(), client, target.IP, port, assistance.Command{Op: "frame", ID: old}); err == nil {
				t.Fatal("old session survived")
			}
			call("end", "", 0, 0)
			d, r := bind.txDirect.Load()-direct, bind.txRelay.Load()-relay
			if route == PathDirect && (d == 0 || r != 0) || route == PathRelay && (r == 0 || d != 0) {
				t.Fatal("unexpected mesh path")
			}
			t.Logf("pending/view/control/revoke/fresh verified, actual Shift and mouse released; direct_tx=%d relay_tx=%d", d, r)
		})
	}
}

var assistUser = windows.NewLazySystemDLL("user32.dll")

func heldAssist(v int) bool {
	x, _, _ := assistUser.NewProc("GetAsyncKeyState").Call(uintptr(v))
	return int16(x) < 0
}

type assistNote struct{ hwnd, edit uintptr }

func openAssistNote(t *testing.T) assistNote {
	path := filepath.Join(t.TempDir(), "Calabi-Assist-Input.txt")
	if e := os.WriteFile(path, []byte("0123456789"), 0600); e != nil {
		t.Fatal(e)
	}
	assistUser.NewProc("SetProcessDPIAware").Call()
	cmd := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "notepad.exe"), path)
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	var h uintptr
	cb := syscall.NewCallback(func(w, _ uintptr) uintptr {
		var pid uint32
		assistUser.NewProc("GetWindowThreadProcessId").Call(w, uintptr(unsafe.Pointer(&pid)))
		if int(pid) == cmd.Process.Pid {
			visible, _, _ := assistUser.NewProc("IsWindowVisible").Call(w)
			if visible != 0 {
				h = w
				return 0
			}
		}
		return 1
	})
	cls, _ := windows.UTF16PtrFromString("Edit")
	for until := time.Now().Add(6 * time.Second); time.Now().Before(until); {
		assistUser.NewProc("EnumWindows").Call(cb, 0)
		if h != 0 {
			edit, _, _ := assistUser.NewProc("FindWindowExW").Call(h, 0, uintptr(unsafe.Pointer(cls)), 0)
			if edit != 0 {
				assistUser.NewProc("SetWindowPos").Call(h, ^uintptr(0), 24, 330, 600, 230, 0x40)
				return assistNote{h, edit}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("dedicated classic Notepad unavailable")
	return assistNote{}
}
func (n assistNote) point(t *testing.T) (int, int) {
	type point struct{ X, Y int32 }
	p := point{25, 10}
	assistUser.NewProc("ClientToScreen").Call(n.edit, uintptr(unsafe.Pointer(&p)))
	// Screen coordinates as seen by the DPI-aware helper.
	w, _, _ := assistUser.NewProc("GetSystemMetrics").Call(0)
	h, _, _ := assistUser.NewProc("GetSystemMetrics").Call(1)
	hit, _, _ := assistUser.NewProc("WindowFromPoint").Call(uintptr(uint64(uint32(p.X)) | uint64(uint32(p.Y))<<32))
	if hit != n.edit {
		t.Fatal("test editor not visible at target point")
	}
	x, y := int(p.X)*65535/int(w), int(p.Y)*65535/int(h)
	if x <= 0 || y <= 0 || x >= 65000 || y >= 65000 {
		t.Fatal("test target outside primary desktop")
	}
	return x, y
}
func (n assistNote) text() string {
	buf := make([]uint16, 128)
	assistUser.NewProc("SendMessageW").Call(n.edit, 0xd, uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0])))
	return windows.UTF16ToString(buf)
}
