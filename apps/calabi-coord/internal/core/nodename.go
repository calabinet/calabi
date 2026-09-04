package core

import (
	"errors"
	"fmt"
	"strings"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// Node names are MagicDNS labels: a peer reaches this node by typing its name
// (the client resolver answers both "<name>" and "<name>.mesh" — see the
// client's magicdns package). That makes the name a DNS label, not free text,
// and it makes it unique within a meshnet: two nodes answering to one name is
// an ambiguous resolve, which is exactly the state the console shows today when
// every daemon registers as "daemon".
//
// The rules here apply to ADMIN renames only. A node's self-reported name (its
// hostname at registration) is left as-is: tightening that would refuse
// registration for machines already enrolled under names like "DESKTOP-AB12",
// which is a data-plane break for a cosmetic gain. The admin-set name is what
// the mesh then uses, so an operator always has a way to get a clean label.
// maxNodeNameLength is one DNS label. Kept as an alias so callers reading this
// file see the limit; the rule is enforced in meshproto.ValidateLabel.
const maxNodeNameLength = meshproto.MaxLabelLength

var (
	// ErrInvalidNodeName is returned for a name that isn't a usable DNS label.
	ErrInvalidNodeName = errors.New("core: invalid node name")
	// ErrNodeNameTaken is returned when another node in the meshnet already
	// answers to that name.
	ErrNodeNameTaken = errors.New("core: node name already in use")
)

// maxNodeTags caps how many tags one node may carry. Tags are ACL selectors, so
// the list is read on every policy evaluation; nothing legitimate needs dozens.
const maxNodeTags = 16

// ErrInvalidNodeTag is returned for a tag that isn't a usable ACL selector.
var ErrInvalidNodeTag = errors.New("core: invalid node tag")

// NormalizeNodeTags lowercases, trims, de-duplicates and validates a tag list.
// A tag is "tag:" plus a DNS-ish label — the same alphabet as a node name,
// because both end up as ACL selectors and a selector that can't be typed
// consistently is a rule that silently matches nothing.
func NormalizeNodeTags(in []string) ([]string, error) {
	if len(in) > maxNodeTags {
		return nil, fmt.Errorf("%w: %d tags (max %d)", ErrInvalidNodeTag, len(in), maxNodeTags)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		t := strings.ToLower(strings.TrimSpace(raw))
		if t == "" {
			continue
		}
		label, ok := strings.CutPrefix(t, "tag:")
		if !ok {
			return nil, fmt.Errorf("%w: %q must start with \"tag:\"", ErrInvalidNodeTag, raw)
		}
		if err := ValidateNodeName(label); err != nil {
			return nil, fmt.Errorf("%w: %q — %s", ErrInvalidNodeTag, raw, err)
		}
		if seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out, nil
}

// NormalizeNodeName lowercases and trims a candidate name. DNS labels are
// case-insensitive, so storing the lowercase form keeps uniqueness checks and
// resolution consistent.
func NormalizeNodeName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// ValidateNodeName checks that name is a usable MagicDNS label: 1.63 chars of
// [a-z0-9-], not starting or ending with "-". Expects an already-normalized
// name. Pure.
// The rule itself lives in the shared contract module so the CLIENT can apply
// the identical one before declaring anything. It has to be the same rule, not
// a similar one: a registration skips unusable entries rather than failing, so
// a name the node accepts and this side rejects disappears with nobody saying
// why (see meshproto.ValidateLabel).
func ValidateNodeName(name string) error {
	if err := meshproto.ValidateLabel(name); err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidNodeName,
			strings.TrimPrefix(err.Error(), "invalid label: "))
	}
	return nil
}
