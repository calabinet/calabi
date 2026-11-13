package mesh

import (
	"context"
	"encoding/hex"
	"errors"
	"github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Look up the listener binding first: a stale certificate in the store alone
// is not evidence that TermService is presenting it.
const rdpPinScript = `$ErrorActionPreference='Stop'
$b=Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-tcp'"
if(!$b.SSLCertificateSHA1Hash){exit 1}
$c=Get-ChildItem 'Cert:/LocalMachine/Remote Desktop','Cert:/LocalMachine/My' | Where-Object Thumbprint -eq $b.SSLCertificateSHA1Hash | Select-Object -First 1
if(!$c -or $c.NotAfter -le (Get-Date) -or $c.NotBefore -gt (Get-Date)){exit 1}
[BitConverter]::ToString(([Security.Cryptography.SHA256]::Create()).ComputeHash($c.RawData)).Replace('-','')`

func readRDPPin(ctx context.Context) ([]byte, error) {
	path := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	cmd := exec.CommandContext(ctx, path, "-NoProfile", "-NonInteractive", "-Command", rdpPinScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	b, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	pin, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(pin) != 32 {
		return nil, errors.New("invalid RDP listener fingerprint")
	}
	return pin, nil
}

func startRDPCertificateReporter(ctx context.Context, coord *CoordClient, logger *slog.Logger, refresh <-chan struct{}) {
	if coord.sessionToken() == "" {
		return
	}
	go runRDPCertificateReporter(ctx, coord, logger, refresh, readRDPPin)
}

func runRDPCertificateReporter(ctx context.Context, coord *CoordClient, logger *slog.Logger, refresh <-chan struct{}, readPin func(context.Context) ([]byte, error)) {
	var previous string
	var previousToken string
	reported := false
	for ctx.Err() == nil {
		read, cancel := context.WithTimeout(ctx, 10*time.Second)
		pin, err := readPin(read)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			pin = nil
		}
		// Pins belong to a registration, not just a device. Recovery can
		// replace the token without restarting this transport or goroutine.
		token := coord.sessionToken()
		if !reported || token != previousToken || string(pin) != previous {
			call, stop := context.WithTimeout(ctx, 5*time.Second)
			_, err = coord.rpc.ReportRdpCertificate(call, &meshpb.ReportRdpCertificateRequest{SessionToken: token, Sha256: pin})
			stop()
			if status.Code(err) == codes.Unimplemented {
				return
			}
			if err == nil {
				previous = string(pin)
				previousToken = token
				reported = true
			} else if ctx.Err() == nil {
				logger.Debug("mesh: unable to publish RDP listener fingerprint", "err", err)
			}
		}
		interval := time.Minute
		if len(pin) == 0 || err != nil {
			interval = 15 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-refresh:
		case <-time.After(interval):
		}
	}
}
