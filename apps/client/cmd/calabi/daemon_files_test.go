package main

import (
	"testing"

	"github.com/calabinet/calabi/apps/client/internal/filecontrol"
)

func TestFileControlBoundConsole(t *testing.T) {
	for _, host := range []string{"0.0.0.0", "[::]", "127.0.0.1", "[::1]", "localhost", "192.0.2.1"} {
		t.Run(host, func(t *testing.T) {
			got, err := fileControlConsole("http://" + host + ":7500")
			if err != nil || got != "http://127.0.0.1:7500" {
				t.Fatalf("console=%q error=%v", got, err)
			}
		})
	}
	for _, raw := range []string{"", "http://example.com:7500", "https://0.0.0.0:7500", "http://0.0.0.0:0", "http://0.0.0.0:7500/path", "http://user@0.0.0.0:7500"} {
		if _, err := fileControlConsole(raw); err == nil {
			t.Errorf("accepted invalid bound URL %q", raw)
		}
	}
	for _, raw := range []string{"http://0.0.0.0:7500", "http://[::]:7500", "http://192.0.2.1:7500"} {
		if _, err := filecontrol.EndpointForConsole(raw); err == nil {
			t.Errorf("caller URL validation weakened: %q", raw)
		}
	}
}
