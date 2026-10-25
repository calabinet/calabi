//go:build windows

package filecontrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	winio "github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"io"
	"net"
	"os/user"
	"time"
)

// CreateFile also checks FILE_READ_ATTRIBUTES when opening a pipe. Grant it
// explicitly to desktop users, without FILE_CREATE_PIPE_INSTANCE (bit 4).
const pipeAccess = windows.FILE_READ_DATA | windows.FILE_WRITE_DATA | windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE | windows.READ_CONTROL

func pipeSecurityDescriptor(owner string) string {
	return "O:" + owner + "D:P(A;;GA;;;SY)(A;;GA;;;" + owner + fmt.Sprintf(")(A;;0x%08x;;;AU)", uint32(pipeAccess))
}

func identityForPID(pid uint32) (string, error) {
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(p)
	var tok windows.Token
	if err := windows.OpenProcessToken(p, windows.TOKEN_QUERY, &tok); err != nil {
		return "", err
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
}
func pipeHandle(conn net.Conn) (windows.Handle, error) {
	f, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return 0, errors.New("pipe handle unavailable")
	}
	return windows.Handle(f.Fd()), nil
}

func Serve(ctx context.Context, control *Control, console string) (<-chan error, error) {
	endpoint, err := EndpointForConsole(console)
	if err != nil {
		return nil, err
	}
	return servePipe(ctx, endpoint, control)
}
func servePipe(ctx context.Context, path string, control *Control) (<-chan error, error) {
	self, err := user.Current()
	if err != nil {
		return nil, err
	}
	// Authenticated local users may connect, but cannot create another instance
	// (FILE_CREATE_PIPE_INSTANCE=4 is deliberately absent from their mask).
	sd := pipeSecurityDescriptor(self.Uid)
	listener, err := winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: sd, InputBufferSize: 8192, OutputBufferSize: 8192})
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	done := make(chan error, 1)
	go func() {
		defer stop()
		defer listener.Close()
		slots := make(chan struct{}, 8)
		for {
			conn, err := listener.Accept()
			if err != nil {
				if ctx.Err() != nil {
					err = nil
				}
				done <- err
				return
			}
			select {
			case slots <- struct{}{}:
			default:
				conn.Close()
				continue
			}
			go func() {
				defer func() { <-slots }()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
				stop := context.AfterFunc(ctx, func() { conn.Close() })
				defer stop()
				h, err := pipeHandle(conn)
				if err != nil {
					return
				}
				var pid uint32
				if windows.GetNamedPipeClientProcessId(h, &pid) != nil {
					return
				}
				principal, err := identityForPID(pid)
				if err != nil {
					return
				}
				var req Request
				dec := json.NewDecoder(io.LimitReader(conn, 16<<10))
				dec.DisallowUnknownFields()
				if dec.Decode(&req) != nil {
					return
				}
				callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer cancel()
				_ = json.NewEncoder(conn).Encode(control.Handle(callCtx, principal, req))
			}()
		}
	}()
	return done, nil
}

func Call(ctx context.Context, console string, req Request) (Snapshot, error) {
	endpoint, err := EndpointForConsole(console)
	if err != nil {
		return Snapshot{}, err
	}
	return callPipe(ctx, endpoint, req)
}
func callPipe(ctx context.Context, path string, req Request) (Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	conn, err := winio.DialPipeAccess(ctx, path, pipeAccess)
	if err != nil {
		return Snapshot{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	h, err := pipeHandle(conn)
	if err != nil {
		return Snapshot{}, err
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return Snapshot{}, err
	}
	ownerSID, _, err := sd.Owner()
	if err != nil {
		return Snapshot{}, err
	}
	owner := ownerSID.String()
	self, err := user.Current()
	if err != nil {
		return Snapshot{}, err
	}
	if owner != "S-1-5-18" && owner != self.Uid {
		return Snapshot{}, errors.New("file metadata pipe is not owned by SYSTEM or the current user")
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return Snapshot{}, err
	}
	var response Response
	if err := json.NewDecoder(io.LimitReader(conn, 4<<20)).Decode(&response); err != nil {
		return Snapshot{}, err
	}
	if response.Error != "" {
		return Snapshot{}, errors.New(response.Error)
	}
	return response.Snapshot, nil
}
