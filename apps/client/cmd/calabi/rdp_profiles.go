package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/png"
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
	Thumbnail string `json:"thumbnail,omitempty"`
	Peer      string `json:"peer"`
	Name      string `json:"name"`
	IP        string `json:"ip"`
	Account   string `json:"account"`
	UsedAt    int64  `json:"used_at"`
	Port      uint16 `json:"port,omitempty"`
	HostKey   string `json:"host_key,omitempty"`
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
		records, err := readRemoteRecent(d.dir, filename)
		if err == nil {
			for i := range records {
				records[i].Thumbnail = readRDPPreview(d.dir, profile, records[i].Peer)
			}
		}
		return records, err
	}
	for _, member := range v.Members {
		if !member.CanRDPLogin() || member.DeviceKey != a.Peer || member.IP == v.Overlay {
			continue
		}
		if a.Action == "rdp_target" {
			return map[string]string{"host": member.IP, "local": v.Overlay, "scope": v.Scope, "pin": member.RDPPin,
				"profile": profile, "credential_key": rdpHash(profile + "\x00" + member.DeviceKey)}, nil
		}
		if a.Action == "rdp_preview" {
			if a.RDPProfile != profile {
				return nil, errors.New("Remote login profile changed")
			}
			records, err := readRemoteRecent(d.dir, filename)
			if err != nil {
				return nil, err
			}
			for _, record := range records {
				if record.Peer == a.Peer {
					return nil, writeRDPPreview(d.dir, profile, a.Peer, a.RDPPreview)
				}
			}
			return nil, errors.New("Remote login record no longer exists")
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
		if err := writeRemoteRecent(d.dir, filename, updated); err != nil {
			return nil, err
		}
		for _, record := range records {
			keep := false
			for _, retained := range updated {
				if retained.Peer == record.Peer {
					keep = true
					break
				}
			}
			if !keep {
				_ = os.Remove(filepath.Join(d.dir, rdpPreviewName(profile, record.Peer)))
			}
		}
		return nil, nil
	}
	return nil, errors.New("RDP target is no longer an authorized Windows device")
}

func rdpPreviewName(profile, peer string) string {
	return "rdp-preview-" + rdpHash(profile+"\x00"+peer) + ".png"
}

func readRDPPreview(dir, profile, peer string) string {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return ""
	}
	defer root.Close()
	f, err := root.Open(rdpPreviewName(profile, peer))
	if err != nil {
		return ""
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 96*1024+1))
	if err != nil || len(data) > 96*1024 {
		return ""
	}
	config, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil || config.Width > 192 || config.Height > 108 {
		return ""
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(data)
}

func writeRDPPreview(dir, profile, peer, encoded string) error {
	if len(encoded) < 12 || len(encoded) > (2+192*108*4)*2 {
		return errors.New("Invalid remote preview")
	}
	raw, err := hex.DecodeString(encoded)
	if err != nil {
		return errors.New("Invalid remote preview")
	}
	w, h := int(raw[0]), int(raw[1])
	if w == 0 || h == 0 || w > 192 || h > 108 || len(raw) != 2+w*h*4 {
		return errors.New("Invalid remote preview")
	}
	picture := image.NewNRGBA(image.Rect(0, 0, w, h))
	copy(picture.Pix, raw[2:])
	f, err := os.CreateTemp(dir, "rdp-preview-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		err = png.Encode(f, picture)
	}
	if err == nil {
		err = f.Sync()
	}
	if err = errors.Join(err, f.Close()); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(dir, rdpPreviewName(profile, peer)))
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
