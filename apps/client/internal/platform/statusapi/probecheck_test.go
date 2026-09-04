package statusapi

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// End-to-end through the mux: the wizard POSTs {type, local_addr} and gets a
// probe result back.
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

	s := New(nil, Config{BFFConsoleURL: "http://127.0.0.1:0"})
	mux := http.NewServeMux()
	s.Register(mux)

	post := func(body string) (int, map[string]any) {
		req := httptest.NewRequest("POST", "/v1/probe/check", strings.NewReader(body))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		var out map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out
	}

	code, out := post(`{"type":"tcp","local_addr":"` + ln.Addr().String() + `"}`)
	if code != http.StatusOK {
		t.Fatalf("live listener: status %d body %v", code, out)
	}
	if out["healthy"] != true {
		t.Errorf("live listener: healthy = %v, want true (%v)", out["healthy"], out)
	}

	// A public target must be refused, and refused as a normal 200 answer with
	// a reason — the SPA renders healthy:false as a hint, not an error toast.
	code, out = post(`{"type":"tcp","local_addr":"1.1.1.1:80"}`)
	if code != http.StatusOK {
		t.Fatalf("public target: status %d body %v", code, out)
	}
	if out["healthy"] != false {
		t.Errorf("public target: healthy = %v, want false", out["healthy"])
	}
	if e, _ := out["error"].(string); !strings.Contains(e, "public address") {
		t.Errorf("public target: error = %q, want the public-address rule named", e)
	}

	if code, _ := post(`{"type":"http","local_addr":""}`); code != http.StatusBadRequest {
		t.Errorf("empty local_addr: status %d, want 400", code)
	}
	if code, _ := post(`not json`); code != http.StatusBadRequest {
		t.Errorf("bad json: status %d, want 400", code)
	}

	// GET must not reach the handler — the route is POST-only.
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/v1/probe/check?local_addr=1.1.1.1:80", nil))
	if rr.Code == http.StatusOK {
		t.Errorf("GET /v1/probe/check = 200, want it rejected (POST-only)")
	}
}
