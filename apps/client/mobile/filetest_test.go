package mobile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileExperimentIsDisabledByDefault(t *testing.T) {
	c := newTestCore(t, &fakeBFF{}, &fakePlatform{})
	for _, path := range []string{"/v1/filetest", "/v1/filetest/start", "/v1/filetest/decide", "/v1/filetest/stop", "/v1/filetest/clear"} {
		method := "POST"
		if path == "/v1/filetest" {
			method = "GET"
		}
		if r := c.Call(method, path, []byte(`{}`)); r.Status != 404 {
			t.Fatalf("disabled %s: %d", path, r.Status)
		}
	}
	if c.fileTest != nil {
		t.Fatal("disabled test generated an identity or listener")
	}
}

func TestExplicitClearOnlyRemovesPrivateP0InboxFiles(t *testing.T) {
	dir := t.TempDir()
	inbox, err := os.MkdirTemp(dir, "filetest-p0-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inbox, strings.Repeat("a", 64)+".received"), []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(dir, "other-file.txt")
	if err := os.WriteFile(keep, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := clearFileTestInboxes(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(inbox); !os.IsNotExist(err) {
		t.Fatal("P0 inbox was not cleared")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatal("clear touched unrelated data")
	}
	unexpected, _ := os.MkdirTemp(dir, "filetest-p0-")
	_ = os.WriteFile(filepath.Join(unexpected, "keep.txt"), nil, 0600)
	if err := clearFileTestInboxes(dir); err == nil {
		t.Fatal("clear accepted an unrecognized file")
	}
}

func TestFileExperimentRequiresConnectedMeshAndExplicitPeer(t *testing.T) {
	c := newTestCore(t, &fakeBFF{}, &fakePlatform{})
	c.cfg.FileTransferP0 = true
	c.api = c.routes()
	code, identity := call(t, c, "GET", "/v1/filetest", "")
	if code != 200 || len(identity["fingerprint"].(string)) != 64 || identity["running"] != false {
		t.Fatalf("identity: %d %v", code, identity)
	}
	if code, _ := call(t, c, "POST", "/v1/filetest/start", `{"peer_ip":"100.64.0.7","fingerprint":"bad"}`); code != 400 {
		t.Fatal("accepted invalid pairing")
	}
	if code, _ := call(t, c, "POST", "/v1/filetest/start", `{"peer_ip":"100.64.0.7","fingerprint":"0000000000000000000000000000000000000000000000000000000000000000"}`); code != 409 {
		t.Fatal("started without a mesh session")
	}
	if c.fileTest.r != nil {
		t.Fatal("disconnected experiment opened an inbox")
	}
}
