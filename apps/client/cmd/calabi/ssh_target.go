package main

import (
	"errors"
	"net/netip"
	"strings"
	"time"
	"unicode"

	"github.com/calabinet/calabi/apps/client/internal/filecontrol"
)

var sshMeshIPv4 = netip.MustParsePrefix("100.64.0.0/10")

func (d *desktopFileAgent) sshAction(a fileAction) (any, error) {
	v, err := filecontrol.Call(d.ctx, d.console, filecontrol.Request{Op: "snapshot", Lease: d.lease})
	if err != nil {
		return nil, err
	}
	if !v.Ready || v.Scope == "" {
		return nil, errors.New("Mesh is not ready")
	}
	profile := rdpProfile(v)
	file := "ssh-recent-" + profile + ".json"
	switch a.Action {
	case "ssh_history":
		records, err := readRemoteRecent(d.dir, file)
		return map[string]any{"records": records, "profile": profile}, err
	case "ssh_record":
		target, err := sshTarget(v, a.Peer)
		if err != nil {
			return nil, err
		}
		if a.RDPProfile != profile || a.SSHPort == 0 || a.RDPAccount == "" || len(a.RDPAccount) > 128 ||
			strings.ContainsFunc(a.RDPAccount, unicode.IsControl) {
			return nil, errors.New("Invalid SSH login record")
		}
		name := []rune(a.RDPName)
		records, err := readRemoteRecent(d.dir, file)
		if err != nil {
			return nil, err
		}
		updated := []remoteRecent{{
			Peer: a.Peer, Name: string(name[:min(len(name), 120)]), IP: target["host"],
			Account: a.RDPAccount, Port: a.SSHPort, HostKey: target["host_key"], UsedAt: time.Now().UnixMilli(),
		}}
		for _, record := range records {
			if len(updated) < 32 && (record.Peer != a.Peer || record.Account != a.RDPAccount || record.Port != a.SSHPort) {
				updated = append(updated, record)
			}
		}
		return nil, writeRemoteRecent(d.dir, file, updated)
	default:
		return sshTarget(v, a.Peer)
	}
}

func sshTarget(view filecontrol.Snapshot, peer string) (map[string]string, error) {
	local, err := netip.ParseAddr(view.Overlay)
	if !view.Ready || view.Scope == "" || err != nil || !sshMeshIPv4.Contains(local) {
		return nil, errors.New("Mesh is not ready")
	}
	for _, member := range view.Members {
		if peer == "" || member.DeviceKey != peer || member.OS != "linux" {
			continue
		}
		host, err := netip.ParseAddr(member.IP)
		if err == nil && host != local && sshMeshIPv4.Contains(host) {
			profile := rdpProfile(view)
			return map[string]string{
				"host": host.String(), "local": local.String(), "profile": profile,
				"host_key": rdpHash(profile + "\x00" + peer),
			}, nil
		}
	}
	return nil, errors.New("Linux SSH target is no longer available in this mesh")
}
