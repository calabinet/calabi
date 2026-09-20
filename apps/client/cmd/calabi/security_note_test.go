// security_note_test.go — the "these flags were not applied" note follows the
// EDGE's answer, not the client's own declaration.
//
// THE BUG. Whether a client-supplied policy is honoured is decided edge-side:
// standalone mode AND no control plane wired. The CLI keyed its note off
// `--standalone` / `calabi mode standalone` instead — a local declaration — and
// suppressed the note whenever it was set. A BYOI edge is standalone in spirit
// and control-plane-wired in fact, so it does NOT apply client policy: the user
// declared standalone, the note went quiet, --basic-auth went nowhere (the edge
// drops it, tunnel-svc keeps only the IP rules), and the tunnel had no password
// while everyone believed it did. Nothing in the row, nothing in either console,
// nothing in any log.
//
// A flag may not silence a fact it has no part in deciding.
//
// RUN: go test./apps/client/cmd/calabi/ -run TestSecurityNote -v
package main

import (
	"io"
	"os"
	"strings"
	"testing"

	proto "github.com/calabinet/calabi/pkg/protocol"
)

// captureStderr runs fn with os.Stderr redirected and returns what it wrote.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	saved := os.Stderr
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	_ = w.Close()
	os.Stderr = saved
	return <-done
}

// flagsWithBasicAuth returns a securityFlags that has already built its blob,
// so l7Proposed is populated the way a real run populates it.
func flagsWithBasicAuth(t *testing.T, standalone bool) *securityFlags {
	t.Helper()
	sf := &securityFlags{l7: true, standalone: standalone}
	sf.basicAuth = stringList{"alice:s3cret"}
	if _, err := sf.buildConfigJSON(); err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	if len(sf.l7Proposed) == 0 {
		t.Fatal("precondition: --basic-auth should be recorded as an L7 proposal")
	}
	return sf
}

// The case that cost a tunnel its password: the user declared standalone, and
// the edge — BYOI, control-plane-wired — did not apply the policy.
func TestSecurityNoteDeclaringStandaloneCannotSilenceTheEdgesAnswer(t *testing.T) {
	sf := flagsWithBasicAuth(t, true)
	out := captureStderr(t, func() { sf.NoteEdgePolicy(proto.ClientPolicyRelayed) })

	if !strings.Contains(out, "--basic-auth") {
		t.Fatalf("the edge said it did not apply the policy and the user was not told.\n"+
			"stderr was: %q", out)
	}
	if !strings.Contains(out, "NOT applied") {
		t.Fatalf("the note must say plainly that nothing was applied: %q", out)
	}
}

// Proposing and applying are different: when the edge DID apply it, warning
// about it is the "footgun warning that is wrong" this file exists to avoid.
func TestSecurityNoteSilentWhenTheEdgeAppliedIt(t *testing.T) {
	for _, standalone := range []bool{false, true} {
		sf := flagsWithBasicAuth(t, standalone)
		out := captureStderr(t, func() { sf.NoteEdgePolicy(proto.ClientPolicyApplied) })
		if out != "" {
			t.Fatalf("standalone=%v: the policy WAS applied; nothing to warn about, got %q",
				standalone, out)
		}
	}
}

// An edge too old to answer leaves the client with only its own guess. That is
// the one place the declaration still gets to decide — and the only place.
func TestSecurityNoteFallsBackToTheGuessOnlyForAnEdgeThatSaysNothing(t *testing.T) {
	quiet := flagsWithBasicAuth(t, true)
	if out := captureStderr(t, func() { quiet.NoteEdgePolicy("") }); out != "" {
		t.Fatalf("old edge + declared standalone: no better answer exists, got %q", out)
	}

	loud := flagsWithBasicAuth(t, false)
	if out := captureStderr(t, func() { loud.NoteEdgePolicy("") }); !strings.Contains(out, "--basic-auth") {
		t.Fatalf("old edge + no declaration: keep the pre-existing warning, got %q", out)
	}
}

// Nothing L7 was passed, so there is nothing to report however the edge answers.
// `calabi http 8080` and `calabi http 8080 --ip-allow …` must stay clean.
func TestSecurityNoteSilentWhenNoL7FlagsWerePassed(t *testing.T) {
	sf := &securityFlags{l7: true}
	sf.ipAllow = stringList{"203.0.113.0/24"}
	if _, err := sf.buildConfigJSON(); err != nil {
		t.Fatal(err)
	}
	for _, r := range []proto.ClientPolicyResult{"", proto.ClientPolicyRelayed, proto.ClientPolicyApplied} {
		if out := captureStderr(t, func() { sf.NoteEdgePolicy(r) }); out != "" {
			t.Fatalf("result=%q: ip rules apply everywhere; got %q", r, out)
		}
	}
}
