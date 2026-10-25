//go:build linux || darwin

package filecontrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func socketPath(console string, uid int) (string, error) {
	endpoint, err := EndpointForConsole(console)
	if err != nil {
		return "", err
	}
	port := endpoint[strings.LastIndex(endpoint, ".")+1:]
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return "", err
	}
	return filepath.Join(socketDirectory(uid), "console-"+port+".sock"), nil
}

func ownDirectory(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	var info unix.Stat_t
	if err := unix.Lstat(dir, &info); err != nil {
		return err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || info.Uid != uint32(os.Geteuid()) || st.Mode().Perm()&0022 != 0 {
		return errors.New("file-control directory must be owned by daemon UID and not writable by other users")
	}
	return os.Chmod(dir, 0755)
}

func Serve(ctx context.Context, control *Control, console string) (<-chan error, error) {
	path, err := socketPath(console, os.Geteuid())
	if err != nil {
		return nil, err
	}
	if err := ownDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	return serveUnix(ctx, control, path)
}

func serveUnix(ctx context.Context, control *Control, path string) (<-chan error, error) {
	// Remove only an owned, stale socket. Never unlink another user's object.
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err == nil {
		if st.Uid != uint32(os.Geteuid()) || st.Mode&unix.S_IFMT != unix.S_IFSOCK {
			return nil, errors.New("file-control path is not an owned socket")
		}
		probe, err := net.DialTimeout("unix", path, 200*time.Millisecond)
		if err == nil {
			probe.Close()
			return nil, errors.New("file-control socket already active")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0666); err != nil {
		listener.Close()
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	done := make(chan error, 1)
	go func() {
		defer stop()
		defer listener.Close()
		slots := make(chan struct{}, 8)
		for {
			conn, err := listener.AcceptUnix()
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
				uid, err := peerUID(conn)
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
				_ = json.NewEncoder(conn).Encode(control.Handle(callCtx, fmt.Sprintf("uid:%d", uid), req))
			}()
		}
	}()
	return done, nil
}

func Call(ctx context.Context, console string, req Request) (Snapshot, error) {
	var errs []error
	for _, uid := range []int{0, os.Geteuid()} {
		path, err := socketPath(console, uid)
		if err != nil {
			return Snapshot{}, err
		}
		view, err := callUnix(ctx, path, req)
		if err == nil {
			return view, nil
		}
		// Fall back only when the root daemon's endpoint does not exist. An
		// authorization or RPC failure must not redirect a root session to a
		// different user daemon that happens to reuse its console port.
		if !errors.Is(err, os.ErrNotExist) {
			return Snapshot{}, err
		}
		errs = append(errs, err)
		if uid == os.Geteuid() {
			break
		}
	}
	return Snapshot{}, fmt.Errorf("file-control socket unavailable; update/restart the matching daemon: %w", errors.Join(errs...))
}

func callUnix(ctx context.Context, path string, req Request) (Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return Snapshot{}, err
	}
	defer conn.Close()
	u, ok := conn.(*net.UnixConn)
	if !ok {
		return Snapshot{}, errors.New("not a Unix socket")
	}
	uid, err := peerUID(u)
	if err != nil {
		return Snapshot{}, err
	}
	if uid != 0 && uid != uint32(os.Geteuid()) {
		return Snapshot{}, errors.New("file-control server is not root or current UID")
	}
	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
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
