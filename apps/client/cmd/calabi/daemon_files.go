package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/calabinet/calabi/apps/client/internal/filecontrol"
	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
	"github.com/calabinet/calabi/apps/client/internal/mesh"
	"github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"log/slog"
	"net"
	"net/url"
	"runtime"
	"time"
)

// The URL returned by our own listener may contain a wildcard or interface IP.
// IPC uses its actual port as the daemon identifier, always through loopback.
// Keep this normalization separate from validation of caller-supplied URLs.
func fileControlConsole(bound string) (string, error) {
	u, err := url.Parse(bound)
	if err != nil {
		return "", err
	}
	if u.Hostname() != "localhost" && net.ParseIP(u.Hostname()) == nil {
		return "", errors.New("daemon console must have a bound IP address")
	}
	u.Host = net.JoinHostPort("127.0.0.1", u.Port())
	console := u.String()
	if _, err := filecontrol.EndpointForConsole(console); err != nil {
		return "", err
	}
	return console, nil
}

type fileRunnerSource interface{ fileRunner() *meshRunner }

func (l *runnerLease) fileRunner() *meshRunner { return l.r }

func startFileControl(ctx context.Context, logger *slog.Logger, source any, console string) func() {
	noop := func() {}
	if console == "" {
		return noop // The console is disabled or has not started.
	}
	current := func() (*meshRunner, int64) {
		switch s := source.(type) {
		case *localMesh:
			return s.runner(), 0
		case *platformMeshController:
			s.mu.Lock()
			defer s.mu.Unlock()
			if l, ok := s.lease.(fileRunnerSource); ok {
				return l.fileRunner(), s.leaseOrgID
			}
		}
		return nil, 0
	}
	controller := func() (*mesh.Controller, filecontrol.Snapshot, error) {
		r, org := current()
		if r == nil {
			return nil, filecontrol.Snapshot{}, errors.New("mesh is not connected")
		}
		r.mu.Lock()
		ctrl := r.ctrl
		r.mu.Unlock()
		st := r.MeshStatus()
		if ctrl == nil || !ctrl.FileTransferReady() || !st.Up || st.Overlay == "" {
			return nil, filecontrol.Snapshot{}, errors.New("coordinator does not support file transfer or mesh is not ready")
		}
		view := filecontrol.Snapshot{Ready: true, Scope: fmt.Sprintf("%s/%d/%d/%s", r.cfg.Coord, org, ctrl.FileNodeID(), ctrl.Params.NodeKey.String()), NodeKey: ctrl.Params.NodeKey.String(), Overlay: st.Overlay, RelayKbps: ctrl.FileRelayLimit(), Peers: []filecontrol.Peer{}}
		for _, p := range ctrl.FilePeers() {
			_, pin, ok := ctrl.FilePeer(p.Overlay)
			if !ok {
				continue
			}
			path := ""
			for _, live := range st.Peers {
				if live.PublicKey == p.NodeKey.String() {
					path = live.Path
					break
				}
			}
			view.Peers = append(view.Peers, filecontrol.Peer{Grant: filetransfer.Grant{Path: path, Peer: filetransfer.Peer{IP: p.Overlay, Fingerprint: pin}, DeviceKey: p.NodeKey.String(), Port: uint16(p.FileTransfer.Port), Receiving: p.FileTransfer.Receiving}, Name: p.Name, Incoming: r.IncomingTCPAllowed(p.Overlay, 17401), ExpiresUnix: p.FileTransfer.ExpiresUnix})
		}
		for _, p := range ctrl.FileMembers() {
			view.Members = append(view.Members, filecontrol.Member{IP: p.Overlay.String(), DeviceKey: p.NodeKey.String(), Incoming: r.IncomingTCPAllowed(p.Overlay, 17401)})
		}
		return ctrl, view, nil
	}
	ctl := &filecontrol.Control{Source: filecontrol.Source{Receiving: filecontrol.ReceptionFirewall(), View: func() (filecontrol.Snapshot, error) { _, view, err := controller(); return view, err }, Publish: func(ctx context.Context, scope string, info *meshpb.FileTransferInfo) error {
		ctrl, view, err := controller()
		if err != nil {
			return err
		}
		if scope != view.Scope {
			return errors.New("mesh session changed")
		}
		return ctrl.PublishFileTransfer(ctx, info)
	}}}
	console, err := fileControlConsole(console)
	if err != nil {
		logger.Warn("file user-agent console address unavailable", "error", err)
		return noop
	}
	ctx, cancel := context.WithCancel(ctx)
	if err := ctl.StopReception(ctx); err != nil {
		logger.Warn("file reception firewall reset failed", "error", err)
	}
	done, err := filecontrol.Serve(ctx, ctl, console)
	if err != nil {
		if runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
			logger.Warn("file user-agent metadata IPC unavailable", "error", err)
		} else {
			logger.Debug("file user-agent metadata IPC unavailable", "error", err)
		}
		cancel()
		return noop
	}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := ctl.StopReception(cleanup); err != nil {
				logger.Warn("file reception firewall cleanup failed", "error", err)
			}
		}()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := ctl.ReconcileReception(ctx); err != nil {
					logger.Warn("file reception firewall lease cleanup failed", "error", err)
				}
			}
		}
	}()
	go func() {
		if err := <-done; err != nil {
			logger.Warn("file user-agent metadata IPC stopped", "error", err)
		}
	}()
	return func() {
		cancel()
		select {
		case <-stopped:
		case <-time.After(10 * time.Second):
			logger.Warn("file reception firewall cleanup did not finish before shutdown")
		}
	}
}
