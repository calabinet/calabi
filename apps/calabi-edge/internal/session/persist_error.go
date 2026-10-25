package session

// persist_error.go — classifying a persister failure for the wire.
//
// handleNewProxy used to answer every definitive persist failure with
// CodeProxyDuplicate, because when that branch was written the only one was the
// (edge_node_id, remote_port) unique check. An org security baseline is a
// second, and it is nothing to do with duplication: a client switching on the
// numeric code — which is what codes are for — branched wrong, and the sentence
// the control plane had written for a human arrived wrapped in the transport's
// own envelope.

import (
	"errors"

	proto "github.com/calabinet/calabi/pkg/protocol"
	"github.com/calabinet/calabi/pkg/protocol/usererror"
)

// ErrProxyPolicyRequired marks a persist failure caused by the organization's
// access-protection baseline.
//
// Declared HERE, in the open tree, and wrapped by the PLATFORM adapter — which
// is the only side that knows gRPC status codes. This package cannot import
// them (internal/session and internal/listener must build without
// internal/platform/*), so the seam is a sentinel the adapter tags on and this
// side matches with errors.Is. A standalone edge has no persister that can
// produce it, and nothing here needs to know that.
var ErrProxyPolicyRequired = errors.New("tunnel refused: the organization requires access protection")

// ErrProxyAwaitingApproval marks a persist/claim that produced a tunnel the
// organization has not approved yet.
//
// Same seam as above, and the same reason it is declared here. Note what it is
// NOT: a failure. The row was created and kept; an admin approving it is the
// whole remedy, and nothing the client can change would help. The daemon says
// so and stops rather than retrying.
var ErrProxyAwaitingApproval = errors.New("tunnel awaiting approval: an admin of this organization has to approve it before it serves")

// ErrProxyRefused marks a persist the control plane refused for a reason of
// its own that is neither of the above — a custom domain that is not the
// org's, for one. Same seam. It exists so those stop being read as the
// baseline: for a while every refusal of that kind reached the client as
// CodeProxyPolicyRequired, and the client printed "this organization requires
// every tunnel to have access protection" in front of a sentence about a
// domain.
var ErrProxyRefused = errors.New("tunnel refused by the control plane")

// Refused tags kind (one of the sentinels above) onto the control plane's own
// sentence. Error() is that sentence and nothing else — it is what the client
// is shown, and the sentinel's text in front of it, or the transport's, is noise
// the reader has to get past. The adapter used to wrap with fmt.Errorf, which
// put both there and kept persistErrorMessage from ever seeing the envelope it
// strips.
func Refused(kind error, msg string) error { return &refusal{kind: kind, msg: msg} }

type refusal struct {
	kind error
	msg  string
}

func (r *refusal) Error() string { return r.msg }
func (r *refusal) Unwrap() error { return r.kind }

// persistErrorCode picks the wire code for a definitive persist failure.
//
// The default stays CodeProxyDuplicate: that is what this branch was built for,
// and an unrecognised failure is likelier to be a collision than anything else.
func persistErrorCode(err error) int {
	if errors.Is(err, ErrProxyPolicyRequired) {
		return proto.CodeProxyPolicyRequired
	}
	if errors.Is(err, ErrProxyAwaitingApproval) {
		return proto.CodeProxyAwaitingApproval
	}
	if errors.Is(err, ErrProxyRefused) {
		return proto.CodeForbidden
	}
	return proto.CodeProxyDuplicate
}

// persistErrorMessage keeps business refusals and hides internal RPC failures.
func persistErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	msg, _ := usererror.Message(400, err.Error())
	return msg
}
