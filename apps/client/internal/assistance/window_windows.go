package assistance

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

//go:embed Window.cs
var source []byte

type nativeWindow struct {
	in       io.WriteCloser
	out      *bufio.Reader
	exitCode int
	stopped  chan struct{}
}

func (w *nativeWindow) done() <-chan struct{} { return w.stopped }
func (w *nativeWindow) close()                { w.in.Close() }

// Called only after stopped is closed.
func (w *nativeWindow) outcome() string {
	if w.exitCode>>16 == 1 {
		return fmt.Sprintf("desktop_capture_win32_%d", w.exitCode&0xffff)
	}
	switch w.exitCode {
	case 41:
		return "declined"
	case 42:
		return "stopped"
	case 43:
		return "viewer_idle_timeout"
	case 44:
		return "consent_timeout"
	case 45:
		return "desktop_session_changed"
	case 46:
		return "helper_pipe_closed"
	}
	return fmt.Sprintf("helper_exit_%d", w.exitCode)
}
func openWindow(ctx context.Context, label string) (window, error) {
	// Static bootstrap only. All peer-controlled values travel through stdin.
	const bootstrap = `$ErrorActionPreference='Stop';$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::ReadLine()));Add-Type -TypeDefinition $s -ReferencedAssemblies System.Windows.Forms,System.Drawing,System.Web.Extensions;[CalabiConsent]::Run();exit ([CalabiConsent]::Outcome)`
	exe := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	cmd := exec.Command(exe, "-NoProfile", "-NonInteractive", "-STA", "-Command", bootstrap)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	w := &nativeWindow{in: in, out: bufio.NewReader(stdout), stopped: make(chan struct{})}
	go func() { cmd.Wait(); w.exitCode = cmd.ProcessState.ExitCode(); close(w.stopped) }()
	go func() {
		select {
		case <-ctx.Done():
			w.close()
		case <-w.stopped:
		}
	}()
	startup := time.AfterFunc(15*time.Second, func() { _ = cmd.Process.Kill() })
	defer startup.Stop()
	if _, err = fmt.Fprintln(in, base64.StdEncoding.EncodeToString(source)); err == nil {
		_, err = fmt.Fprintln(in, base64.StdEncoding.EncodeToString([]byte(label)))
	}
	if err == nil {
		var line string
		line, err = w.out.ReadString('\n')
		if err == nil && line != "ready\r\n" && line != "ready\n" {
			err = fmt.Errorf("assistance window startup failed")
		}
	}
	if err != nil {
		w.close()
		return nil, err
	}
	return w, nil
}
func (w *nativeWindow) call(c Command) (Reply, error) {
	var result Reply
	body, _ := json.Marshal(c)
	if _, err := fmt.Fprintln(w.in, base64.StdEncoding.EncodeToString(body)); err != nil {
		return result, err
	}
	line, err := w.out.ReadBytes('\n')
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(line, &result)
	return result, err
}
