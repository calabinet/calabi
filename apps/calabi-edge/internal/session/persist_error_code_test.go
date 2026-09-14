// persist_error_code_test.go — what the client is told when a persist is
// refused.
//
// THE BUG. handleNewProxy wrapped EVERY persister failure as
// CodeProxyDuplicate ("this proxy/port already exists"), because when that
// branch was written the only definitive failure was the
// (edge_node_id, remote_port) unique check. It is not any more: an org security
// baseline can refuse a create outright. So a user running
//
//	calabi http 8080
//
// in an org that requires access protection got:
//
//	calabi: code=3001 rpc error: code = FailedPrecondition desc = this
//	organization requires every tunnel to have access protection ...
//
// A code that says "duplicate", a message that says "unprotected", and a raw
// gRPC envelope around the one sentence written for a human to read. Anything
// switching on the numeric code — and that is what codes are for — branches
// wrong.
//
// The classification has to cross the open-tree/platform seam: only the
// platform adapter knows gRPC status codes, and this package must not import
// them. So the adapter tags the error with a sentinel declared here, and this
// package asks errors.Is.
//
// RUN: go test./apps/calabi-edge/internal/session/ -run TestPersistError -v
package session

import (
	"errors"
	"fmt"
	"testing"

	proto "github.com/calabi/calabi/pkg/protocol"
)

// A refusal the user can act on gets its own code, distinct from "duplicate".
func TestPersistErrorPolicyRefusalHasItsOwnCode(t *testing.T) {
	if proto.CodeProxyPolicyRequired == proto.CodeProxyDuplicate {
		t.Fatal("the policy refusal shares a code with a port collision; a client " +
			"cannot tell them apart")
	}
	err := fmt.Errorf("this organization requires every tunnel to have access "+
		"protection: %w", ErrProxyPolicyRequired)
	if got := persistErrorCode(err); got != proto.CodeProxyPolicyRequired {
		t.Fatalf("persistErrorCode = %d, want %d (CodeProxyPolicyRequired)",
			got, proto.CodeProxyPolicyRequired)
	}
}

// The control: an untagged failure still reads as a duplicate, which is what
// the (edge_node_id, remote_port) collision this branch was built for is.
func TestPersistErrorControlPlainFailureStaysDuplicate(t *testing.T) {
	if got := persistErrorCode(errors.New("boom")); got != proto.CodeProxyDuplicate {
		t.Fatalf("persistErrorCode = %d, want %d (CodeProxyDuplicate)",
			got, proto.CodeProxyDuplicate)
	}
	if got := persistErrorCode(nil); got != proto.CodeProxyDuplicate {
		t.Fatalf("persistErrorCode(nil) = %d, want the duplicate default", got)
	}
}

// The message reaches the user without the transport's envelope around it. It
// was written to tell somebody at a terminal what to do; "rpc error: code =
// FailedPrecondition desc =" in front of it is noise the reader has to parse
// past, and it names a layer they cannot act on.
func TestPersistErrorMessageIsNotWrappedInGRPCNoise(t *testing.T) {
	raw := "rpc error: code = FailedPrecondition desc = this organization requires " +
		"every tunnel to have access protection before it is published."
	got := persistErrorMessage(errors.New(raw))
	if got == raw {
		t.Fatalf("the gRPC envelope was passed through verbatim:\n  %s", got)
	}
	if want := "this organization requires"; got[:len(want)] != want {
		t.Fatalf("message = %q, want it to start with the sentence written for the user", got)
	}
}

// An error with no envelope is left exactly as it is — the stripper must not
// start editing messages it does not recognise.
func TestPersistErrorControlPlainMessageUntouched(t *testing.T) {
	const plain = "remote port 20001 is already in use on this edge"
	if got := persistErrorMessage(errors.New(plain)); got != plain {
		t.Fatalf("a plain message was rewritten: %q -> %q", plain, got)
	}
}
