package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestFileStdioStartupError(t *testing.T) {
	if os.Getenv("CALABI_TEST_STDIO_STARTUP_ERROR") == "1" {
		os.Exit(runMeshFiles([]string{"--stdio", "--console", "http://example.com:7400"}))
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestFileStdioStartupError$")
	cmd.Env = append(os.Environ(), "CALABI_TEST_STDIO_STARTUP_ERROR=1")
	out, err := cmd.Output()
	if _, ok := err.(*exec.ExitError); !ok {
		t.Fatalf("expected failed initialization, got %v", err)
	}
	var response map[string]string
	if err := json.Unmarshal(out, &response); err != nil {
		t.Fatalf("startup error not returned on private JSON channel: %q: %v", out, err)
	}
	if !strings.Contains(response["error"], "exact local daemon console URL required") {
		t.Fatalf("initialization cause missing: %q", out)
	}
}
