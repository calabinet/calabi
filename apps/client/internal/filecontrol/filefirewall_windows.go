//go:build windows

package filecontrol

import (
	"context"
	_ "embed"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

//go:embed filefirewall_windows.ps1
var fileFirewallScript string

// ReceptionFirewall only manages the installer's enrolled rule for this exact
// executable. The callback is used after OS identity, lease and signature checks.
func ReceptionFirewall() func(context.Context, bool) error {
	// Ordinary-user/dev daemons keep the existing manual-firewall behavior.
	// Never prompt for elevation from a desktop agent or a background poll.
	if !windows.GetCurrentProcessToken().IsElevated() {
		return nil
	}
	var mu sync.Mutex
	var known, active bool
	return func(ctx context.Context, receiving bool) error {
		mu.Lock()
		defer mu.Unlock()
		if known && active == receiving {
			return nil
		}
		if err := applyInstalledFileFirewall(ctx, receiving); err != nil {
			return err
		}
		known, active = true, receiving
		return nil
	}
}

func applyInstalledFileFirewall(ctx context.Context, receiving bool) error {
	program, err := os.Executable()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	return executeFileFirewall(ctx, fileFirewallCommand(program, receiving))
}

// InstallationFirewall is the explicit elevated enrollment/removal entry point.
// Its program scope always comes from the invoking binary, never a CLI path.
func InstallationFirewall(ctx context.Context, install bool) error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return fmt.Errorf("file firewall installation requires administrator privileges")
	}
	program, err := os.Executable()
	if err != nil {
		return err
	}
	action := "Remove"
	if install {
		action = "Install"
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return executeFileFirewall(ctx, fileFirewallActionCommand(program, action, "off"))
}

func executeFileFirewall(ctx context.Context, encoded string) error {
	powershell := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	cmd := exec.CommandContext(ctx, powershell, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("file reception firewall: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func fileFirewallCommand(program string, receiving bool) string {
	state := "off"
	if receiving {
		state = "on"
	}
	return fileFirewallActionCommand(program, "Apply", state)
}

func fileFirewallActionCommand(program, action, state string) string {
	command := "& {\n" + fileFirewallScript + "\n} -Action " + action + " -Receiving " + state + " -Program '" + strings.ReplaceAll(program, "'", "''") + "'"
	units := utf16.Encode([]rune(command))
	bytes := make([]byte, 2*len(units))
	for i, unit := range units {
		bytes[2*i], bytes[2*i+1] = byte(unit), byte(unit>>8)
	}
	return base64.StdEncoding.EncodeToString(bytes)
}
