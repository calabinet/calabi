package mobilecheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const module = "github.com/calabi/calabi/apps/client"

// mobilePackages is what the phone core builds on. A package joins the list
// the moment the mobile core imports it, not when it happens to be clean.
var mobilePackages = []string{
	module + "/mobile",
	module + "/internal/mesh/...",
	module + "/internal/hostnet",
	module + "/internal/wake",
	module + "/internal/creds",
	module + "/internal/platform/bffclient",
	module + "/internal/platform/meshenroll",
	module + "/internal/trust",
	module + "/internal/selfhosted",
}

// forbidden is checked against every transitive dependency. os/exec is the
// structural test; the named packages are desktop-only and are listed so the
// failure names the culprit rather than only its symptom.
var forbidden = map[string]string{
	"os/exec":                               "iOS forbids fork and Android apps have no root: route, DNS and firewall changes go through the platform instead",
	module + "/internal/status":             "the :7400 console and its embedded SPA",
	module + "/internal/platform/statusapi": "the :7400 API; the phone core exposes its own subset",
	module + "/internal/selfupdate":         "phones update through the store",
	module + "/internal/inspect":            "per-tunnel capture buffers; phones run no tunnels",
	module + "/internal/probe":              "listening-socket enumeration shells out to netstat on macOS",
}

// goTool and goEnv are captured in init, which runs BEFORE TestMain enters the
// testhome sandbox. The go command is a developer tool, not code under test: it
// keeps its build cache, module cache and telemetry under the per-user
// directories, and pointed into the empty sandbox it would both build cold and
// trip testhome's "tests wrote into the per-user directories" check.
var (
	goTool string
	goEnv  []string
)

func init() {
	goEnv = os.Environ()
	goTool = filepath.Join(runtime.GOROOT(), "bin", "go")
	if _, err := os.Stat(goTool); err != nil {
		goTool, _ = exec.LookPath("go")
	}
}

func TestMobilePackagesStayPortable(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-builds for android and ios")
	}
	if goTool == "" {
		t.Skip("go tool not found")
	}
	for _, goos := range []string{"android", "ios"} {
		t.Run(goos, func(t *testing.T) {
			env := append(append([]string(nil), goEnv...), "GOOS="+goos, "GOARCH=arm64", "CGO_ENABLED=0")
			run := func(args ...string) string {
				t.Helper()
				cmd := exec.Command(goTool, args...)
				cmd.Env = env
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, out)
				}
				return string(out)
			}
			run(append([]string{"build"}, mobilePackages...)...)
			deps := run(append([]string{"list", "-deps"}, mobilePackages...)...)
			for _, dep := range strings.Fields(deps) {
				if why, bad := forbidden[dep]; bad {
					t.Errorf("GOOS=%s build of the mobile packages depends on %s (%s). Find the importer with: GOOS=%s go list -deps -f '{{.ImportPath}}: {{.Imports}}' %s",
						goos, dep, why, goos, strings.Join(mobilePackages, " "))
				}
			}
		})
	}
}
