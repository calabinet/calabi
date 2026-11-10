package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	winio "github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func runBackgroundFileAgent(attach bool, console string) int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	account, err := user.Current()
	if err == nil {
		var session uint32
		err = windows.ProcessIdToSessionId(uint32(os.Getpid()), &session)
		if err == nil {
			if session == 0 {
				err = errors.New("file agent requires an interactive Windows user session")
			} else {
				// A Windows user has one file identity, cache and daemon lease.
				// A second session of that user must not attach or start a rival.
				path := backgroundFileAgentPath(account.Uid)
				if attach {
					err = attachBackgroundFileAgent(ctx, path, account.Uid, session)
				} else {
					err = runInteractiveFileAgent(ctx, path, account.Uid, session, console)
				}
			}
		}
	}
	if err == nil {
		return 0
	}
	if attach {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"error": "Cannot connect to the Windows file agent: " + err.Error()})
	} else {
		fmt.Fprintln(os.Stderr, "Windows file agent:", err)
	}
	return 1
}

func backgroundFileAgentPath(sid string) string { return `\\.\pipe\Calabi.DesktopFiles.v1.` + sid }

var (
	fileAgentWTS      = windows.NewLazySystemDLL("wtsapi32.dll")
	fileAgentWTSQuery = fileAgentWTS.NewProc("WTSQuerySessionInformationW")
	fileAgentWTSFree  = fileAgentWTS.NewProc("WTSFreeMemory")
)

const (
	fileAgentDesktopClient byte = iota
	fileAgentConsoleClient
)

func fileAgentSessionActive(session uint32) bool {
	const wtsConnectState = 8
	const wtsActive = 0
	var state *uint32
	var size uint32
	ok, _, _ := fileAgentWTSQuery.Call(0, uintptr(session), wtsConnectState,
		uintptr(unsafe.Pointer(&state)), uintptr(unsafe.Pointer(&size)))
	if ok == 0 || state == nil {
		return false
	}
	defer fileAgentWTSFree.Call(uintptr(unsafe.Pointer(state)))
	return size == 4 && *state == wtsActive
}

func runInteractiveFileAgent(ctx context.Context, path, sid string, session uint32, console string) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if fileAgentSessionActive(session) {
			active, cancel := context.WithCancel(ctx)
			go func() {
				check := time.NewTicker(time.Second)
				defer check.Stop()
				for {
					select {
					case <-active.Done():
						return
					case <-check.C:
						if !fileAgentSessionActive(session) {
							cancel()
							return
						}
					}
				}
			}()
			err := serveBackgroundFileAgent(active, path, sid, session, console)
			interrupted := active.Err() != nil
			cancel()
			if !interrupted {
				return err
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func listenBackgroundFileAgent(path, sid string) (net.Listener, error) {
	// ListenPipe atomically creates the first instance and rejects remote
	// clients. The owner-only ACL also keeps other local accounts out.
	return winio.ListenPipe(path, &winio.PipeConfig{
		SecurityDescriptor: "O:" + sid + "D:P(A;;GA;;;" + sid + ")",
	})
}

func backgroundFileAgentAlreadyListening(err error) bool {
	// Windows can return ACCESS_DENIED for a second first-instance pipe.
	return errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_ALREADY_EXISTS)
}

func serveBackgroundFileAgent(ctx context.Context, path, sid string, session uint32, console string) error {
	listener, err := listenBackgroundFileAgent(path, sid)
	if backgroundFileAgentAlreadyListening(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer listener.Close()
	// The task may start before the desktop ever runs. Its paste helper still
	// reads the same persisted locale file the desktop writes.
	if os.Getenv("CALABI_UI_LOCALE_FILE") == "" {
		if dir := os.Getenv("LOCALAPPDATA"); dir != "" {
			_ = os.Setenv("CALABI_UI_LOCALE_FILE", filepath.Join(dir, "com.calabi.desktop", "native-ui-language"))
		}
	}
	agent, err := newDesktopFileAgent(ctx, console)
	if err != nil {
		return err
	}
	defer agent.close()
	go agent.keepWindowsPasteHelperRunning()
	return serveBackgroundFileAgentRPC(ctx, listener, session, agent.handle, agent.handleConsoleAction)
}

func (d *desktopFileAgent) keepWindowsPasteHelperRunning() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			if !d.shellPasteLive.Load() {
				d.opMu.Lock()
				if d.ctx.Err() == nil {
					d.startShellPaste()
				}
				d.opMu.Unlock()
			}
		}
	}
}

func serveBackgroundFileAgentRPC(ctx context.Context, listener net.Listener, session uint32, desktop, console func(fileAction) (any, error)) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	slots := make(chan struct{}, 4)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				defer conn.Close()
				stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
				defer stop()
				if checkFileAgentPipeSession(conn, windows.GetNamedPipeClientProcessId, session) != nil {
					return
				}
				_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				var client [1]byte
				if _, err := io.ReadFull(conn, client[:]); err != nil {
					return
				}
				_ = conn.SetReadDeadline(time.Time{})
				// The stdio relay fixes the client byte before forwarding
				// any desktop input. Only a local CLI may supply paths.
				switch client[0] {
				case fileAgentDesktopClient:
					serveFileActions(conn, conn, desktop)
				case fileAgentConsoleClient:
					serveFileActions(conn, conn, console)
				}
			}()
		default:
			_ = conn.Close()
		}
	}
}

func checkFileAgentPipeSession(conn net.Conn, getPID func(windows.Handle, *uint32) error, session uint32) error {
	handle := windows.Handle(conn.(interface{ Fd() uintptr }).Fd())
	var pid, peerSession uint32
	if err := getPID(handle, &pid); err != nil {
		return err
	}
	if err := windows.ProcessIdToSessionId(pid, &peerSession); err != nil {
		return err
	}
	if peerSession != session {
		return errors.New("the Windows file agent belongs to another sign-in session")
	}
	return nil
}

func dialBackgroundFileAgent(ctx context.Context, path, sid string, session uint32) (net.Conn, error) {
	const access = windows.FILE_READ_DATA | windows.FILE_WRITE_DATA | windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE | windows.READ_CONTROL
	conn, err := winio.DialPipeAccess(ctx, path, access)
	if err != nil {
		return nil, err
	}
	handle := windows.Handle(conn.(interface{ Fd() uintptr }).Fd())
	if err := func() error {
		info, err := windows.GetSecurityInfo(handle, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
		if err != nil {
			return err
		}
		owner, _, err := info.Owner()
		if err != nil {
			return err
		}
		if owner.String() != sid {
			return errors.New("the Windows file agent pipe is not owned by the current user")
		}
		return checkFileAgentPipeSession(conn, windows.GetNamedPipeServerProcessId, session)
	}(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func attachBackgroundFileAgent(ctx context.Context, path, sid string, session uint32) error {
	startup, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	conn, err := dialBackgroundFileAgent(startup, path, sid, session)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		// An already signed-in user may open Calabi immediately after an
		// upgrade. Start the same broker on demand without tying its lifetime
		// to this stdio relay. The pipe arbitrates concurrent starts.
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		cmd := exec.Command(exe, "mesh", "files", "--background")
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
		if err := cmd.Start(); err != nil {
			return err
		}
		go func() { _ = cmd.Wait() }()
		for {
			conn, err = dialBackgroundFileAgent(startup, path, sid, session)
			if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
				break
			}
			select {
			case <-startup.Done():
				return startup.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if _, err := conn.Write([]byte{fileAgentDesktopClient}); err != nil {
		return err
	}
	go func() {
		_, _ = io.Copy(conn, os.Stdin)
		_ = conn.Close()
	}()
	// The shell owns this relay only. Closing either stream must never shut
	// down the clipboard listener or its helper.
	_, err = io.Copy(os.Stdout, conn)
	return err
}

func connectFileConsole(ctx context.Context, console string) (bool, int) {
	if console != "http://127.0.0.1:7400" && console != "http://127.0.0.1:7400/" {
		return false, 0
	}
	account, err := user.Current()
	if err != nil {
		return false, 0
	}
	var session uint32
	if windows.ProcessIdToSessionId(uint32(os.Getpid()), &session) != nil || session == 0 {
		return false, 0
	}
	dial, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	conn, err := dialBackgroundFileAgent(dial, backgroundFileAgentPath(account.Uid), account.Uid, session)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return false, 0
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Windows file agent:", err)
		return true, 1
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if _, err := conn.Write([]byte{fileAgentConsoleClient}); err != nil {
		fmt.Fprintln(os.Stderr, "Windows file agent:", err)
		return true, 1
	}
	writer, reader := json.NewEncoder(conn), json.NewDecoder(conn)
	return true, runFileConsole(ctx, func(action fileAction) (any, error) {
		if action.Action == "console_stage" || action.Action == "console_export" {
			// Preserve paths relative to the invoking terminal's directory.
			path, err := filepath.Abs(action.Paths[0])
			if err != nil {
				return nil, err
			}
			action.Paths[0] = path
		}
		if err := writer.Encode(action); err != nil {
			return nil, err
		}
		var result json.RawMessage
		if err := reader.Decode(&result); err != nil {
			return nil, err
		}
		var response struct{ Error string }
		if json.Unmarshal(result, &response) == nil && response.Error != "" {
			return nil, errors.New(response.Error)
		}
		return result, nil
	})
}
