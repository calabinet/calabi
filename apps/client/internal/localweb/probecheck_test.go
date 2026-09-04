package localweb

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The SPA is shared between the platform and standalone paths, so the wizard's
// reachability check has to answer here too — not 404 on standalone.
func TestProbeCheckEndpoint(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	mux := http.NewServeMux()
	New(Config{}).Register(mux)

	post := func(body string) (int, map[string]any) {
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest("POST", "/v1/probe/check", strings.NewReader(body)))
		var out map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out
	}

	code, out := post(`{"type":"tcp","local_addr":"` + ln.Addr().String() + `"}`)
	if code != http.StatusOK || out["healthy"] != true {
		t.Fatalf("live listener: status %d body %v", code, out)
	}

	code, out = post(`{"type":"tcp","local_addr":"1.1.1.1:80"}`)
	if code != http.StatusOK || out["healthy"] != false {
		t.Fatalf("public target: status %d body %v", code, out)
	}
	if e, _ := out["error"].(string); !strings.Contains(e, "public address") {
		t.Errorf("public target: error = %q, want the public-address rule named", e)
	}

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/v1/probe/check", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /v1/probe/check = %d, want 405", rr.Code)
	}
}
