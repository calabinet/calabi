package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
)

func runMeshFileTest(args []string) int {
	if err := meshFileTest(args); err != nil {
		fmt.Fprintf(os.Stderr, "calabi mesh filetest: %v\n", err)
		return 1
	}
	return 0
}

// filetest stays in the invoking user's process. It never installs a file
// listener in the machine-wide privileged daemon or accepts peer-supplied paths.
func meshFileTest(args []string) error {
	fs := flag.NewFlagSet("mesh filetest", flag.ContinueOnError)
	peerStr := fs.String("peer", "", "paired device's exact mesh IP")
	pin := fs.String("pin", "", "paired device's transfer SHA-256 fingerprint (prompt if omitted)")
	port := fs.Int("port", 17401, "P0 transfer port on both devices; must be allowed by mesh ACL")
	kbps := fs.Int("kbps", filetransfer.DefaultKbps, "aggregate file rate ceiling in kbps (1024 bits)")
	send := fs.String("send", "", "local file to send; otherwise receive with explicit confirmation")
	inbox := fs.String("inbox", "", "existing parent directory for a new private P0 inbox (required for receiving)")
	maxBytes := fs.Int64("max-bytes", 8<<30, "total P0 inbox byte limit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	if inServiceManager {
		return errors.New("filetest must run in a local user's terminal")
	}
	account, err := user.Current()
	if err != nil {
		return err
	}
	if account.Uid == "0" || account.Uid == "S-1-5-18" || account.Uid == "S-1-5-19" || account.Uid == "S-1-5-20" {
		return errors.New("P0 filetest cannot run as root or a system service account")
	}
	ip, err := netip.ParseAddr(*peerStr)
	if err != nil {
		return errors.New("--peer must be an exact mesh IP")
	}
	pacer, err := filetransfer.NewPacer(*kbps)
	if err != nil {
		return err
	}
	state, base, err := fileTestMeshState("")
	if err != nil {
		return err
	}
	local, err := netip.ParseAddr(state.Overlay)
	if err != nil || !state.Up {
		return errors.New("local daemon has no active mesh address")
	}
	key, _ := fileTestPolicy(context.Background(), base, ip, *port)
	if key == "" {
		return errors.New("peer is not an exact device address in the local mesh map")
	}
	identity, err := filetransfer.NewIdentity()
	if err != nil {
		return err
	}
	fmt.Printf("P0 experiment; local IP %s\nTransfer fingerprint: %s\n", local, identity.Fingerprint)
	scanner := bufio.NewScanner(os.Stdin)
	if *pin == "" {
		fmt.Print("Verify the fingerprint on the other device and paste it here: ")
		if !scanner.Scan() {
			return errors.New("no paired fingerprint supplied")
		}
		*pin = strings.TrimSpace(scanner.Text())
	}
	peer := filetransfer.Peer{IP: ip, Fingerprint: *pin}
	if err := peer.Validate(); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	var authorized atomic.Bool
	authorized.Store(true)
	// Pin the original daemon, mesh and WireGuard peer identity too. Losing
	// membership, changing organizations or tightening inbound ACL stops.
	validate := func() bool {
		next, _, err := fileTestMeshState(base)
		if err != nil || !next.Up || next.Overlay != local.String() || next.Coord != state.Coord || next.OrgID != state.OrgID {
			return false
		}
		nextKey, inbound := fileTestPolicy(ctx, base, ip, *port)
		return nextKey == key && (*send != "" || inbound)
	}
	if !validate() {
		return errors.New("current mesh membership or inbound policy does not allow the experiment (update the daemon if inbound-check is unavailable)")
	}
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				authorized.Store(false)
				return
			case <-ticker.C:
				if !validate() {
					authorized.Store(false)
					cancel()
					return
				}
			}
		}
	}()
	if *send != "" {
		file, err := os.Open(*send)
		if err != nil {
			return err
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("send source must be a regular file")
		}
		sender, err := filetransfer.NewSender(identity, local, peer, *port, pacer, authorized.Load)
		if err != nil {
			return err
		}
		defer sender.Close()
		var last time.Time
		result, err := sender.Send(ctx, file, info.Name(), info.Size(), func(f filetransfer.Transfer) {
			if time.Since(last) >= time.Second || f.State == "completed" {
				fmt.Printf("%s: %d/%d bytes, ceiling %d kbps\n", f.State, f.Offset, f.Size, pacer.Kbps())
				last = time.Now()
			}
		})
		if err != nil {
			return err
		}
		fmt.Printf("Verified receipt: %s SHA-256 %s\n", result.ID, result.SHA256)
		return nil
	}
	if *inbox == "" {
		return errors.New("receiving requires --inbox with an existing user-owned parent directory")
	}
	dir, err := os.MkdirTemp(*inbox, "calabi-filetest-")
	if err != nil {
		return err
	}
	receiver, err := filetransfer.NewReceiver(filetransfer.ReceiverConfig{Peer: peer, Directory: dir, Kbps: *kbps, MaxBytes: *maxBytes, Allowed: authorized.Load})
	if err != nil {
		_ = os.Remove(dir)
		return err
	}
	addr, err := filetransfer.Address(local, *port)
	if err != nil {
		_ = receiver.Close()
		return err
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		_ = receiver.Close()
		return err
	}
	server, done := receiver.Serve(listener, identity)
	defer func() { authorized.Store(false); _ = server.Close(); <-done; _ = receiver.Close() }()
	fmt.Printf("Listening on %s; inbox %s\nCommands: accept ID, reject ID, cancel ID, quit\n", addr, dir)
	commands := make(chan string)
	go func() {
		defer close(commands)
		for scanner.Scan() {
			select {
			case commands <- scanner.Text():
			case <-ctx.Done():
				return
			}
		}
	}()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	seen := map[string]string{}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case line, ok := <-commands:
			if !ok || strings.TrimSpace(line) == "quit" {
				return nil
			}
			fields := strings.Fields(line)
			if len(fields) != 2 {
				fmt.Println("Use: accept ID, reject ID, cancel ID, quit")
				continue
			}
			var err error
			switch fields[0] {
			case "accept":
				err = receiver.Decide(fields[1], true)
			case "reject":
				err = receiver.Decide(fields[1], false)
			case "cancel":
				err = receiver.Cancel(fields[1])
			default:
				err = errors.New("unknown command")
			}
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		case <-ticker.C:
			for _, f := range receiver.List() {
				if seen[f.ID] == f.State {
					continue
				}
				seen[f.ID] = f.State
				fmt.Printf("%s %s: %q, %d bytes\n", f.State, f.ID, f.Name, f.Size)
				if f.State == "completed" {
					fmt.Printf("Verified file: %s\n", filepath.Join(dir, f.StoredName))
				}
			}
		}
	}
}

func fileTestMeshState(base string) (meshStatusResp, string, error) {
	var st meshStatusResp
	bases := []string{base}
	if base == "" {
		bases = meshConsoleCandidates()
	}
	hc := &http.Client{Timeout: 2 * time.Second}
	for _, candidate := range bases {
		resp, err := hc.Get(candidate + "/v1/mesh")
		if err != nil {
			continue
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&st)
		_ = resp.Body.Close()
		if err == nil && resp.StatusCode == 200 {
			return st, candidate, nil
		}
	}
	return st, base, errors.New("no current daemon mesh snapshot available")
}

func fileTestPolicy(ctx context.Context, base string, peer netip.Addr, port int) (string, bool) {
	query := url.Values{"source": {peer.String()}, "port": {strconv.Itoa(port)}}
	req, err := http.NewRequestWithContext(ctx, "GET", base+"/v1/mesh/inbound-check?"+query.Encode(), nil)
	if err != nil {
		return "", false
	}
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	var result struct {
		Allowed bool   `json:"allowed"`
		PeerKey string `json:"peer_key"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 1024)).Decode(&result) != nil {
		return "", false
	}
	return result.PeerKey, result.Allowed
}
