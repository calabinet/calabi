// register_error_test.go — the line a person at the terminal reads when the
// edge refuses a tunnel.
//
// RUN: go test ./apps/client/cmd/calabi/ -run TestRegisterError -v
package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	proto "github.com/calabinet/calabi/pkg/protocol"
)

func printed(err error) string {
	var b bytes.Buffer
	printRegisterError(&b, err)
	return strings.TrimSpace(b.String())
}

// A custom domain that is not the org's is not the protection baseline, and the
// line must not say it is. The edge used to send it as CodeProxyPolicyRequired;
// it now sends CodeForbidden with tunnel-svc's sentence.
func TestRegisterErrorDomainRefusalIsNotCalledAProtectionRule(t *testing.T) {
	const msg = "custom domain \"shop.example.com\" is not registered; run `calabi domains create shop.example.com` first"
	got := printed(fmt.Errorf("register: %w", &proto.ErrorPayload{
		Code: proto.CodeForbidden, MessageKey: "calabi.err.proxy.persist_failed", MessageEN: msg,
	}))
	if strings.Contains(got, "access protection") {
		t.Fatalf("a domain refusal was printed as the protection rule:\n  %s", got)
	}
	if !strings.Contains(got, msg) {
		t.Fatalf("the domain sentence is missing:\n  %s", got)
	}
}

// The baseline's own sentence is printed as the edge sent it. Putting a fixed
// "requires every tunnel to have access protection" in front of it doubled the
// sentence for the broad rule and contradicted the narrow one, which is about
// raw-port tunnels only.
func TestRegisterErrorBaselineSentenceIsPrintedAsWritten(t *testing.T) {
	for _, msg := range []string{
		"this organization requires every tunnel to have access protection before it is published. " +
			"Add an IP allowlist, HTTP Basic auth, or an OAuth login to this tunnel in the console.",
		"this organization requires every raw-port tunnel (tcp, udp, sni) to carry an IP allow list " +
			"before it is published. Add an allow list to this tunnel in the console, or pass --ip-allow.",
	} {
		got := printed(&proto.ErrorPayload{Code: proto.CodeProxyPolicyRequired, MessageEN: msg})
		if want := "calabi: " + msg; got != want {
			t.Fatalf("printed:\n  %s\nwant:\n  %s", got, want)
		}
	}
}

// The control: with nothing from the edge to repeat, the code alone still gets a
// sentence rather than a bare number.
func TestRegisterErrorBaselineWithoutMessageStillSaysWhat(t *testing.T) {
	got := printed(&proto.ErrorPayload{Code: proto.CodeProxyPolicyRequired})
	if !strings.Contains(got, "access protection") {
		t.Fatalf("an empty policy refusal printed nothing a person can act on:\n  %s", got)
	}
}
