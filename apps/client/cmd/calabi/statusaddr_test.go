package main

import (
	"flag"
	"os"
	"strings"
	"testing"
)

func TestApplyStatusAddr(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr string // substring; "" = must succeed
		wantEnv string
		warns   bool
	}{
		{"host and port", "127.0.0.1:7500", "", "127.0.0.1:7500", false},
		{"localhost by name", "localhost:7500", "", "localhost:7500", false},
		{"ipv6 loopback", "[::1]:7500", "", "[::1]:7500", false},
		{"disabled", "disabled", "", "disabled", false},
		{"off", "off", "", "off", false},
		{"whitespace is trimmed", "  127.0.0.1:7500  ", "", "127.0.0.1:7500", false},

		// The likely typo gets the likely fix, not a bind error naming an address
		// the user never typed.
		{"bare port", "7500", "is a port, not an address", "", false},
		{"garbage", "not-an-address", "not host:port", "", false},
		{"no port", "127.0.0.1:", "no valid port", "", false},
		{"port zero", "127.0.0.1:0", "no valid port", "", false},
		{"port too big", "127.0.0.1:70000", "no valid port", "", false},
		{"empty", "   ", "empty", "", false},

		// Allowed — the published Docker image documents it — but never silent.
		{"all interfaces", "0.0.0.0:7400", "", "0.0.0.0:7400", true},
		{"empty host is all interfaces", ":7400", "", ":7400", true},
		{"a LAN address", "192.168.1.22:7400", "", "192.168.1.22:7400", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("CALABI_STATUS_ADDR", "sentinel")
			warning, err := applyStatusAddr(c.in)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, c.wantErr)
				}
				// A rejected address must not have been applied.
				if got := os.Getenv("CALABI_STATUS_ADDR"); got != "sentinel" {
					t.Errorf("a rejected address was applied anyway: %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := os.Getenv("CALABI_STATUS_ADDR"); got != c.wantEnv {
				t.Errorf("CALABI_STATUS_ADDR = %q, want %q", got, c.wantEnv)
			}
			if (warning != "") != c.warns {
				t.Errorf("warning = %q, want warns=%v", warning, c.warns)
			}
		})
	}
}

// The flag defaults to the environment, so the env still works and the flag
// beats it — the shape every other override in this CLI has.
func TestStatusAddrFlagDefaultsToTheEnvironment(t *testing.T) {
	t.Setenv("CALABI_STATUS_ADDR", "127.0.0.1:7788")
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	got := registerStatusAddrFlag(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if *got != "127.0.0.1:7788" {
		t.Errorf("with no flag: %q, want the env value", *got)
	}

	fs = flag.NewFlagSet("t", flag.ContinueOnError)
	got = registerStatusAddrFlag(fs)
	if err := fs.Parse([]string{"--status-addr", "127.0.0.1:7799"}); err != nil {
		t.Fatal(err)
	}
	if *got != "127.0.0.1:7799" {
		t.Errorf("with the flag: %q, want the flag to win over the env", *got)
	}
}

// valueFlagsOf must name every flag that eats the following token, and no
// boolean. The second half matters as much as the first: a bool in the list
// swallows whatever comes after it.
func TestValueFlagsOf(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.String("name", "", "")
	fs.Bool("verbose", false, "")
	fs.Int("rate", 0, "")
	fs.Var(&stringList{}, "ip-allow", "")

	got := map[string]bool{}
	for _, n := range valueFlagsOf(fs) {
		got[n] = true
	}
	for _, want := range []string{"name", "rate", "ip-allow"} {
		if !got[want] {
			t.Errorf("%q missing — reorderArgs would leave its value behind as a positional", want)
		}
	}
	if got["verbose"] {
		t.Error("a boolean flag is listed; it would swallow the token after it")
	}
}

// Why the list is derived rather than written by hand: an omission does not
// fail, it MISPARSES. The unlisted flag takes the next flag's NAME as its value
// and the command runs with something plausible-looking and wrong.
//
// This is not hypothetical — `daemon` gained --alias-routes in 4153af64 and the
// hand-written list did not.
func TestReorderArgsMisparsesAnUnlistedValueFlag(t *testing.T) {
	args := []string{"--alias-routes", "192.168.1.0/24", "--advertise-routes", "10.0.0.0/8"}

	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	alias := fs.String("alias-routes", "", "")
	advertise := fs.String("advertise-routes", "", "")

	// Derived from the FlagSet: both survive.
	if err := fs.Parse(reorderArgs(args, valueFlagsOf(fs))); err != nil {
		t.Fatal(err)
	}
	if *alias != "192.168.1.0/24" || *advertise != "10.0.0.0/8" {
		t.Fatalf("derived list: alias=%q advertise=%q, want the values as typed", *alias, *advertise)
	}

	// Hand-written and missing one: the bug this replaced.
	fs2 := flag.NewFlagSet("t", flag.ContinueOnError)
	alias2 := fs2.String("alias-routes", "", "")
	_ = fs2.String("advertise-routes", "", "")
	if err := fs2.Parse(reorderArgs(args, []string{"advertise-routes"})); err != nil {
		t.Fatal(err)
	}
	if *alias2 != "--advertise-routes" {
		t.Fatalf("expected the omission to misparse alias-routes as %q, got %q — "+
			"if this now passes cleanly, reorderArgs changed and this test's premise is stale",
			"--advertise-routes", *alias2)
	}
}
