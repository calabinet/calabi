// Stand-in for calabi.exe in the POSTINSTALL scenarios of ../run.ps1.
//
// The installer hook runs `calabi.exe daemon install --system --platform` and
// then `calabi.exe daemon start`. This program answers those two the way the
// scenario asks, so the hook can be watched handling each answer without a real
// service, a real service manager, or administrator rights.
//
// What it does is set by the environment the test launches the installer with
// (a child of the installer inherits it):
//
//	CALABI_FAKE_INSTALL  "ok"     register: write ImagePath under CALABI_FAKE_REGKEY, exit 0
//	                     "exists" what an UPGRADE gets: the service is already
//	                              there, so install fails — and that is fine
//	                     "refuse" what a refused install prints; nothing is registered
//	CALABI_FAKE_START    "ok" | "fail"
//	CALABI_FAKE_REGKEY   the fake service key, e.g. HKCU\Software\CalabiNsisHookTest\svc
//	CALABI_FAKE_LOG      a file each invocation's arguments are appended to, so
//	                     the test can see WHAT the hook ran and in what order
//
// Built by run.ps1 with `go build`; standard library only.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func main() {
	args := strings.Join(os.Args[1:], " ")
	if p := os.Getenv("CALABI_FAKE_LOG"); p != "" {
		if f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
			fmt.Fprintln(f, args)
			f.Close()
		}
	}

	switch {
	case strings.HasPrefix(args, "daemon install"):
		switch os.Getenv("CALABI_FAKE_INSTALL") {
		case "refuse":
			// The real refusal, first lines: this is the text the installer has
			// to put in front of the user.
			fmt.Fprintln(os.Stderr, "calabi daemon install: this client is in standalone mode, but `daemon install` without --config registers a PLATFORM")
			fmt.Fprintln(os.Stderr, "service - and the mode does not follow the install.")
			os.Exit(1)
		case "exists":
			fmt.Fprintln(os.Stderr, "install: Init already exists: calabi")
			os.Exit(1)
		default:
			key := os.Getenv("CALABI_FAKE_REGKEY")
			if key == "" {
				fmt.Fprintln(os.Stderr, "fakedaemon: CALABI_FAKE_REGKEY is not set")
				os.Exit(1)
			}
			out, err := exec.Command("reg.exe", "add", key, "/v", "ImagePath", "/t", "REG_SZ", "/d", "registered-by-fakedaemon", "/f").CombinedOutput()
			if err != nil {
				fmt.Fprintln(os.Stderr, "fakedaemon: reg add failed:", err, string(out))
				os.Exit(1)
			}
			fmt.Println(`  installed (service "calabi"). start with:  calabi daemon start`)
		}
	case strings.HasPrefix(args, "daemon start"):
		if os.Getenv("CALABI_FAKE_START") == "fail" {
			fmt.Fprintln(os.Stderr, "start: The service did not respond to the start or control request in a timely fashion.")
			os.Exit(1)
		}
		fmt.Println("  start requested.")
	default:
		fmt.Fprintln(os.Stderr, "fakedaemon: unexpected arguments:", args)
		os.Exit(2)
	}
}
