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
	"strings"

	proto "github.com/calabinet/calabi/pkg/protocol"
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
	return proto.CodeProxyDuplicate
}

// grpcErrPrefix is what google.golang.org/grpc's status.Error stringifies to.
// Matched as a literal rather than parsed with the grpc packages, which this
// side of the seam must not import.
const grpcErrPrefix = "rpc error: code = "

// persistErrorMessage returns the persister's message without the gRPC envelope
// the transport wraps it in.
//
// "rpc error: code = FailedPrecondition desc = this organization requires …" is
// read by somebody at a terminal who then has to parse past a naming of a layer
// they cannot act on. Anything that does not carry the envelope is returned
// untouched — a stripper that starts editing messages it does not recognise is
// worse than no stripper.
func persistErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if !strings.HasPrefix(msg, grpcErrPrefix) {
		return msg
	}
	const sep = " desc = "
	if i := strings.Index(msg, sep); i >= 0 {
		return msg[i+len(sep):]
	}
	return msg
}
