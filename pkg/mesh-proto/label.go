package meshproto

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Node and service labels.
//
// This lives in the shared contract module rather than in the coordinator
// because BOTH sides need the same rule, and the cost of them disagreeing is
// not a rejected input — it is a SILENTLY DROPPED one. The coordinator skips
// unusable entries in a registration rather than refusing the whole thing (one
// bad line in a service unit must not keep a machine off the mesh), so a name
// the node happily accepted and the coordinator quietly discarded shows up as
// "I declared it and the console doesn't list it", with nothing anywhere saying
// why.
//
// The rule itself is "one DNS label" because that is what these names ARE: a
// node name is resolved by MagicDNS, and a service name is an ACL selector
// written as svc:<name>. Neither can carry a space, an uppercase letter or a
// dot and still mean what it says.

// MaxLabelLength is one DNS label.
const MaxLabelLength = 63

// ErrInvalidLabel is the sentinel for a name that is not a usable label.
var ErrInvalidLabel = errors.New("invalid label")

// NormalizeLabel lowercases and trims. Labels are case-insensitive, so storing
// the lowercase form keeps uniqueness checks and resolution consistent.
func NormalizeLabel(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// ValidateLabel checks 1.63 characters of [a-z0-9-], not starting or ending
// with "-". Expects an already-normalized value. Pure.
//
// The returned error names the offending character: "invalid" alone leaves
// someone staring at a name that looks fine, which for a space is exactly the
// case — it is invisible in most of the places these names get typed.
func ValidateLabel(s string) error {
	if s == "" {
		return fmt.Errorf("%w: name is empty", ErrInvalidLabel)
	}
	if len(s) > MaxLabelLength {
		return fmt.Errorf("%w: %d characters (max %d)", ErrInvalidLabel, len(s), MaxLabelLength)
	}
	if strings.HasPrefix(s, "-") || strings.HasSuffix(s, "-") {
		return fmt.Errorf(`%w: cannot start or end with "-"`, ErrInvalidLabel)
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		default:
			return fmt.Errorf("%w: %q is not allowed (use a-z, 0-9 and -)", ErrInvalidLabel, r)
		}
	}
	return nil
}

// ValidateHostPort checks an explicit "host:port" target. Empty is always fine
// (it means loopback on the service's own port).
//
// Shared for the same reason as ValidateLabel: an unusable target is SKIPPED at
// registration, not rejected, so a value the node accepted and the coordinator
// discarded leaves a service that exists locally and nowhere else.
func ValidateHostPort(target string) error {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("%w: target %q: want host:port", ErrInvalidLabel, target)
	}
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("%w: target %q: host is empty", ErrInvalidLabel, target)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("%w: target %q: port out of range", ErrInvalidLabel, target)
	}
	return nil
}
