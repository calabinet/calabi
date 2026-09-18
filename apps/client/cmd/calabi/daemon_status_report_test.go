// daemon_status_report_test.go — `calabi daemon status` when the service manager
// will not say.
//
// Reproduced 2026-09-16 on a Windows desktop install, from a non-admin shell:
// the installed, running service answered "status: Access is denied." and exit 1
// — while a service name that does not exist answered "not installed" from the
// same shell. The refusal means the service is there and its state is out of
// reach; its console, on loopback, is not.
//
// RUN: go test./apps/client/cmd/calabi/ -run TestDaemonStatus -v
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/kardianos/service"
)

func runStatusReport(t *testing.T, st service.Status, err error, published string, candidates []string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := reportDaemonStatus(context.Background(), &stdout, &stderr, st, err, published, candidates)
	return code, stdout.String(), stderr.String()
}

func TestDaemonStatusRefusedQueryStillReportsAnInstalledService(t *testing.T) {
	signedIn := serviceModeConsole(t, false)
	refused := fmt.Errorf("open service: %w", os.ErrPermission)

	code, out, errOut := runStatusReport(t, service.StatusUnknown, refused, "", []string{signedIn, "127.0.0.1:1"})
	if code != 0 {
		t.Errorf("exit %d, want 0 — the service is installed, only its state is out of reach", code)
	}
	if errOut != "" {
		t.Errorf("stderr = %q, want nothing: a refusal to answer is not a failure to report", errOut)
	}
	for _, want := range []string{"installed", "not allowed to query", "http://" + signedIn, "keeps its own sign-in"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "not installed") {
		t.Errorf("a refused query reported as not installed:\n%s", out)
	}
}

// When the service's own published console is readable and answers, name that
// one and do not go looking at other ports.
func TestDaemonStatusRefusedQueryPrefersThePublishedConsole(t *testing.T) {
	published := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"state":"connected","connected":true}`))
	}))
	defer published.Close()
	other := serviceModeConsole(t, true)

	_, out, _ := runStatusReport(t, service.StatusUnknown, fmt.Errorf("%w", os.ErrPermission), published.URL, []string{other})
	if !strings.Contains(out, "console: "+published.URL) {
		t.Errorf("published console not named:\n%s", out)
	}
	if strings.Contains(out, other) {
		t.Errorf("probed other ports although the published console answered:\n%s", out)
	}
}

func TestDaemonStatusUnchangedCases(t *testing.T) {
	if code, out, _ := runStatusReport(t, service.StatusUnknown, service.ErrNotInstalled, "", nil); code != 0 || !strings.Contains(out, "not installed") {
		t.Errorf("not installed: exit %d, output %q", code, out)
	}
	if code, _, errOut := runStatusReport(t, service.StatusUnknown, errors.New("systemctl: not found"), "", nil); code != 1 || !strings.Contains(errOut, "systemctl: not found") {
		t.Errorf("other error: exit %d, stderr %q", code, errOut)
	}
	if code, out, _ := runStatusReport(t, service.StatusStopped, nil, "", nil); code != 0 || strings.TrimSpace(out) != "stopped" {
		t.Errorf("stopped: exit %d, output %q", code, out)
	}
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer console.Close()
	if code, out, _ := runStatusReport(t, service.StatusRunning, nil, console.URL, nil); code != 0 ||
		!strings.Contains(out, "running") || !strings.Contains(out, "console: "+console.URL) {
		t.Errorf("running: exit %d, output %q", code, out)
	}
}
