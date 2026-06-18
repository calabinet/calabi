package main

import (
	"path/filepath"
	"testing"
)

// A `daemon install --config X` bakes the LOCAL runner command into the
// service Arguments, with the config path made absolute (the service manager
// launches us from a different working directory).
func TestServiceArguments_LocalConfig(t *testing.T) {
	got := serviceArguments([]string{"--local", "--config", "tunnels.yaml"})
	if len(got) != 4 || got[0] != "daemon" || got[1] != "--local" || got[2] != "--config" {
		t.Fatalf("got %v, want [daemon --local --config <abs>]", got)
	}
	if !filepath.IsAbs(got[3]) {
		t.Errorf("config path not absolutized: %q", got[3])
	}
	if filepath.Base(got[3]) != "tunnels.yaml" {
		t.Errorf("config basename lost: %q", got[3])
	}
}

// No --config → the bare platform daemon command (behaviour).
func TestServiceArguments_NoConfig(t *testing.T) {
	got := serviceArguments([]string{"--name", "d", "--edge-region", "cn-a"})
	if len(got) != 1 || got[0] != "daemon" {
		t.Errorf("got %v, want [daemon]", got)
	}
}

// The --config=value form is recognised too.
func TestServiceArguments_ConfigEqualsForm(t *testing.T) {
	got := serviceArguments([]string{"--config=sub/dir/t.yaml"})
	if len(got) != 4 || !filepath.IsAbs(got[3]) || filepath.Base(got[3]) != "t.yaml" {
		t.Errorf("got %v", got)
	}
}

func TestExtractFlagValue(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"--config", "a.yaml"}, "a.yaml"},
		{[]string{"--config=b.yaml"}, "b.yaml"},
		{[]string{"-config", "c.yaml"}, "c.yaml"},
		{[]string{"-config=d.yaml"}, "d.yaml"},
		{[]string{"--name", "x", "--config", "e.yaml"}, "e.yaml"},
		{[]string{"--name", "x"}, ""},
		{[]string{"--config"}, ""}, // trailing flag, no value
	}
	for _, c := range cases {
		if got := extractFlagValue(c.args, "config"); got != c.want {
			t.Errorf("extractFlagValue(%v) = %q, want %q", c.args, got, c.want)
		}
	}
}
