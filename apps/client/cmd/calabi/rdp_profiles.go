package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/calabinet/calabi/apps/client/internal/filecontrol"
)

type remoteRecent struct {
	Peer    string `json:"peer"`
	Name    string `json:"name"`
	IP      string `json:"ip"`
	Account string `json:"account"`
	UsedAt  int64  `json:"used_at"`
	Port    uint16 `json:"port,omitempty"`
	HostKey string `json:"host_key,omitempty"`
}

func rdpHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func rdpProfile(view filecontrol.Snapshot) string {
	return rdpHash(fmt.Sprintf("%d\x00%s", view.AccountID, view.Scope))
}

func (d *desktopFileAgent) rdpProfileAction(a fileAction) (any, error) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		return nil, errors.New("Windows or macOS desktop required")
	}
	// Re-read authorization even for a record delivered by the native helper.
	v, err := filecontrol.Call(d.ctx, d.console, filecontrol.Request{Op: "snapshot", Lease: d.lease})
	if err != nil {
		return nil, err
	}
	if !v.Ready || v.Scope == "" {
		return nil, errors.New("Mesh is not ready")
	}
	profile := rdpProfile(v)
	filename := "rdp-recent-" + profile + ".json"
	if a.Action == "rdp_history" {
		if a.RDPProfile != "" && a.RDPProfile != profile {
			return nil, errors.New("Remote login profile changed")
		}
		return readRemoteRecent(d.dir, filename)
	}
	for _, member := range v.Members {
		if !member.OwnWindows || member.DeviceKey != a.Peer || member.IP == v.Overlay {
			continue
		}
		if a.Action == "rdp_target" {
			return map[string]string{"host": member.IP, "local": v.Overlay, "scope": v.Scope, "pin": member.RDPPin,
				"profile": profile, "credential_key": rdpHash(profile + "\x00" + member.DeviceKey)}, nil
		}
		if a.RDPProfile != profile || a.RDPAccount == "" || len(a.RDPAccount) > 2047 ||
			!utf8.ValidString(a.RDPAccount) || strings.ContainsFunc(a.RDPAccount, unicode.IsControl) {
			return nil, errors.New("Invalid remote login record")
		}
		records, err := readRemoteRecent(d.dir, filename)
		if err != nil {
			return nil, err
		}
		name := []rune(a.RDPName)
		updated := []remoteRecent{{Peer: member.DeviceKey, Name: string(name[:min(len(name), 120)]), IP: member.IP, Account: a.RDPAccount, Port: a.RDPPort, UsedAt: time.Now().UnixMilli()}}
		for _, record := range records {
			if record.Peer != member.DeviceKey && len(updated) < 32 {
				updated = append(updated, record)
			}
		}
		return nil, writeRemoteRecent(d.dir, filename, updated)
	}
	return nil, errors.New("RDP target is no longer an owned Windows device")
}

func readRemoteRecent(dir, filename string) ([]remoteRecent, error) {
	records := []remoteRecent{}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	f, err := root.Open(filename)
	if errors.Is(err, os.ErrNotExist) {
		return records, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 256*1024+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 256*1024 || json.Unmarshal(data, &records) != nil {
		return nil, errors.New("Invalid remote history")
	}
	return records, nil
}

func writeRemoteRecent(dir, filename string, records []remoteRecent) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	f, err := os.CreateTemp(dir, "remote-recent-*.tmp")
	if err != nil {
		return err
	}
	name := filepath.Base(f.Name())
	defer root.Remove(name)
	err = json.NewEncoder(f).Encode(records)
	if err == nil {
		err = f.Sync()
	}
	if err = errors.Join(err, f.Close()); err != nil {
		return err
	}
	return root.Rename(name, filename)
}
