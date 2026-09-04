package hookspb

import (
	"fmt"

	"google.golang.org/protobuf/proto"
)

// convert.go — cross between a hooks message and the control-plane message it
// mirrors.
//
// Three of the four hook calls restate their control-plane originals
// field-for-field, because those messages were already the narrow thing you
// would design here. The servers that answer these hooks are the same ones that
// own the originals, so something has to cross between the two Go types.
//
// Re-encode rather than ~a dozen hand-written field copies: a hand-written
// converter drifts SILENTLY the day someone adds a field upstream and updates
// only one side. This cannot, because the wire is the single definition of the
// mapping. That the DEFINITIONS still agree is checked separately, by the
// descriptor comparison in identity-svc's hooks_drift_test.go.
//
// Note what this deliberately does NOT cover: ListRelayEndpoints. That one is
// not a mirror — coord read four of EdgeNode's fourteen fields, and the other
// ten are platform-internal — so it is mapped by hand, in the open, where the
// narrowing is visible.
//
// A field present on one side and not the other is DROPPED, not an error. For a
// contract whose whole point is to expose less than the original, that is the
// intended behaviour.

// Convert re-encodes src into dst and returns dst, so a call reads as one
// expression. A nil/invalid src yields the empty dst rather than an error:
// callers treat an absent message as "all defaults".
func Convert[T proto.Message](src proto.Message, dst T) (T, error) {
	if src == nil || !src.ProtoReflect().IsValid() {
		return dst, nil
	}
	b, err := proto.Marshal(src)
	if err != nil {
		return dst, fmt.Errorf("hooks: marshal %s: %w", src.ProtoReflect().Descriptor().FullName(), err)
	}
	if err := proto.Unmarshal(b, dst); err != nil {
		return dst, fmt.Errorf("hooks: unmarshal into %s: %w", dst.ProtoReflect().Descriptor().FullName(), err)
	}
	return dst, nil
}
