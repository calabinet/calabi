//go:build windows

package filecontrol

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Execute the encoded command with a hostile-looking path. The parameter must
// remain literal data when Windows PowerShell parses it.
func TestFileFirewallCommandQuotesProgramPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dir := t.TempDir()
	for _, name := range []string{"USERPROFILE", "HOME", "APPDATA", "LOCALAPPDATA"} {
		t.Setenv(name, dir)
	}
	program := filepath.Join(dir, "测试'; throw 'path was interpreted as code'; #.exe")
	// Run only the parameter parser, without consulting or changing host policy.
	saved := fileFirewallScript
	fileFirewallScript = "param($Action, $Program, $Receiving)\n[Console]::Write($Program)"
	defer func() { fileFirewallScript = saved }()
	ps := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	output, err := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-EncodedCommand", fileFirewallCommand(program, true)).CombinedOutput()
	if err != nil {
		t.Fatalf("unenrolled path must not alter firewall or execute path text: %v: %s", err, output)
	}
	// Windows PowerShell's redirected native output is ANSI on some hosts; use
	// ASCII for the suffix check while still exercising Unicode in the command.
	if !strings.Contains(string(output), "'; throw 'path was interpreted as code'; #.exe") {
		t.Fatalf("path was not passed as literal data: %s", output)
	}
}

func TestInstallationFirewallCommandsUseEmbeddedParser(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"USERPROFILE", "HOME", "APPDATA", "LOCALAPPDATA"} {
		t.Setenv(name, dir)
	}
	// Substitute only the policy body. Exercise the real encoded command and
	// PowerShell parameter parser without consulting the host firewall.
	saved := fileFirewallScript
	fileFirewallScript = "param($Action, $Program, $Receiving)\n[Console]::Write($Action + '|' + $Receiving + '|' + $Program)"
	defer func() { fileFirewallScript = saved }()
	program := filepath.Join(dir, "user's calabi.exe")
	for _, action := range []string{"Install", "Remove"} {
		t.Run(action, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			ps := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
			output, err := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-EncodedCommand", fileFirewallActionCommand(program, action, "off")).CombinedOutput()
			if err != nil || string(output) != action+"|off|"+program {
				t.Fatalf("incorrect embedded invocation: %v: %s", err, output)
			}
		})
	}
}
