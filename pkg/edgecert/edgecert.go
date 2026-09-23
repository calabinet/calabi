// Package edgecert is the one place that knows how an edge node's identity is
// written into, and read out of, its mTLS client certificate.
//
// THE CONTRACT
//
//	CN  = edge-{edge_node_id}-{region}                        every edge
//	SAN = spiffe://calabi/org/{org}/edge/{id}/region/{region}  BYOI edges only
//
// A platform edge carries no org SAN: it serves every organization, so pinning
// it to one would be wrong. A BYOI (single-tenant) edge carries one, and the
// control plane treats it as the authoritative org for everything that node
// says.
//
// # WHY THIS IS A SHARED PACKAGE
//
// Three places used to know this shape independently: cert-svc's edge CA wrote
// it, bff-edge's auth interceptor read it, and the edge's cert-renewal loop
// sniffed it for a spiffe:// URI. Two of those drifting apart fails LOUDLY —
// a certificate nobody can parse authenticates nobody. But the fourth reader,
// added with this package, is the edge deciding its OWN numeric id, and that
// one drifting fails in SILENCE: the node would run happily under an id the
// control plane does not use for it, not recognise its own tunnels, and miss
// every message addressed to it. One parser, so there is nothing to drift.
//
// Stdlib only, on purpose: every side of the contract has to be able to import
// it, including the open-source edge.
package edgecert

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// TrustDomain is the SPIFFE trust domain (the URI host) of every Calabi edge
// certificate. A URI SAN naming any other trust domain is somebody else's and
// is ignored, not rejected.
const TrustDomain = "calabi"

// cnPrefix opens every edge CN. It is what tells an edge cert apart from any
// other leaf the same CA might sign.
const cnPrefix = "edge-"

// Identity is what a certificate says about the edge holding it.
type Identity struct {
	// EdgeNodeID is the node's numeric id in the control plane, from the CN.
	// Always > 0 in a valid identity.
	EdgeNodeID int64
	// Region is the region the node was issued for, from the CN. Never empty
	// in a valid identity.
	Region string
	// OrgID is the single organization a BYOI node is pinned to, from the
	// SPIFFE SAN. ZERO means a PLATFORM node — one that serves every org —
	// not "unknown". Callers that narrow by org must treat 0 as "all", never
	// as a lookup key.
	OrgID int64
	// ServesInbound reports that this certificate can also be presented BY the
	// node, to devices dialing its control listener — nothing in it forbids
	// serverAuth, and it carries a name for the node's public address.
	//
	// That combination is only minted for a BYOI node whose public address was
	// known at issue time, which is what
	// lets one certificate be both the node's client credential to the control
	// plane and its server credential to devices. A platform node gets a
	// client-only leaf here and a separate server certificate.
	//
	// It matters because the failure of getting it wrong is REMOTE: a Go TLS
	// server does not check the EKU of the certificate it serves, the client
	// does. Install a client-only leaf on a listener and the node starts fine
	// and every device fails the handshake.
	ServesInbound bool
}

// IsPlatform reports whether this is a platform (all-org) edge rather than a
// single-tenant BYOI one.
func (i Identity) IsPlatform() bool { return i.OrgID == 0 }

// CommonName renders the CN for an edge certificate. The issuing side
// (cert-svc's edge CA) is the only caller; it exists here so the format string
// lives next to the parser that has to undo it.
func CommonName(edgeNodeID int64, region string) string {
	return fmt.Sprintf("%s%d-%s", cnPrefix, edgeNodeID, region)
}

// SPIFFEURI renders the org SAN pinning a BYOI edge to one organization. Only
// ever added when orgID > 0 — see the package comment.
func SPIFFEURI(orgID, edgeNodeID int64, region string) *url.URL {
	return &url.URL{
		Scheme: "spiffe",
		Host:   TrustDomain,
		Path:   fmt.Sprintf("/org/%d/edge/%d/region/%s", orgID, edgeNodeID, region),
	}
}

// ParseCommonName extracts (edge_node_id, region) from the contract CN form.
// Examples:
//
//	"edge-42-cn-hangzhou"  → id=42, region="cn-hangzhou"
//	"edge-7-ap-singapore"  → id=7,  region="ap-singapore"
//
// The region may itself contain hyphens, so this parses left-to-right rather
// than splitting blindly.
func ParseCommonName(cn string) (int64, string, error) {
	if len(cn) <= len(cnPrefix) || cn[:len(cnPrefix)] != cnPrefix {
		return 0, "", fmt.Errorf("CN %q missing %q prefix", cn, cnPrefix)
	}
	rest := cn[len(cnPrefix):]
	// Find the '-' that terminates the numeric id.
	idEnd := -1
	for i, r := range rest {
		if r == '-' {
			idEnd = i
			break
		}
		if r < '0' || r > '9' {
			return 0, "", fmt.Errorf("CN %q: non-digit %q in edge id", cn, r)
		}
	}
	if idEnd <= 0 || idEnd >= len(rest)-1 {
		return 0, "", fmt.Errorf("CN %q: missing region segment after edge id", cn)
	}
	id, err := strconv.ParseInt(rest[:idEnd], 10, 64)
	if err != nil {
		return 0, "", fmt.Errorf("CN %q: parse id: %w", cn, err)
	}
	if id <= 0 {
		return 0, "", fmt.Errorf("CN %q: edge id must be positive", cn)
	}
	region := rest[idEnd+1:]
	if region == "" {
		return 0, "", fmt.Errorf("CN %q: empty region", cn)
	}
	return id, region, nil
}

// ParseOrgSAN extracts the BYOI (org_id, edge_id) from a certificate's SPIFFE
// URI SAN, if present.
//
// Returns (0, 0, nil) when no such SAN exists — a platform edge whose cert
// carries only the CN. A malformed org/edge segment is a HARD error so a
// tampered SAN cannot silently downgrade itself to "platform".
func ParseOrgSAN(uris []*url.URL) (orgID, edgeNodeID int64, err error) {
	for _, u := range uris {
		if u == nil || u.Scheme != "spiffe" || u.Host != TrustDomain {
			continue
		}
		segs := strings.Split(strings.Trim(u.Path, "/"), "/")
		// Expect at least org/{org}/edge/{id}.
		if len(segs) < 4 || segs[0] != "org" || segs[2] != "edge" {
			return 0, 0, fmt.Errorf("unexpected SPIFFE path %q", u.Path)
		}
		org, oerr := strconv.ParseInt(segs[1], 10, 64)
		if oerr != nil || org <= 0 {
			return 0, 0, fmt.Errorf("bad org segment in SPIFFE SAN %q", u.String())
		}
		eid, eerr := strconv.ParseInt(segs[3], 10, 64)
		if eerr != nil || eid <= 0 {
			return 0, 0, fmt.Errorf("bad edge segment in SPIFFE SAN %q", u.String())
		}
		return org, eid, nil
	}
	return 0, 0, nil
}

// HasOrgSAN reports whether these URIs pin the holder to an organization — the
// cheap "is this a BYOI edge" test, for callers that need the answer but not
// the number. Deliberately looser than ParseOrgSAN: a SPIFFE URI this package
// cannot parse still means somebody meant to pin this cert, and treating it as
// a platform cert would be the dangerous reading.
func HasOrgSAN(uris []*url.URL) bool {
	for _, u := range uris {
		if u != nil && u.Scheme == "spiffe" {
			return true
		}
	}
	return false
}

// FromLeaf reads a whole identity out of a parsed leaf certificate.
//
// It also enforces the one cross-field rule: a SAN naming a different edge id
// than the CN is refused outright, so a certificate cannot claim org X for
// edge A while presenting itself as edge B.
func FromLeaf(leaf *x509.Certificate) (Identity, error) {
	if leaf == nil {
		return Identity{}, fmt.Errorf("edgecert: nil certificate")
	}
	id, region, err := ParseCommonName(leaf.Subject.CommonName)
	if err != nil {
		return Identity{}, fmt.Errorf("edgecert: %w", err)
	}
	orgID, sanEdgeID, err := ParseOrgSAN(leaf.URIs)
	if err != nil {
		return Identity{}, fmt.Errorf("edgecert: %w", err)
	}
	if orgID > 0 && sanEdgeID != id {
		return Identity{}, fmt.Errorf("edgecert: SAN edge id %d != CN edge id %d", sanEdgeID, id)
	}
	return Identity{
		EdgeNodeID:    id,
		Region:        region,
		OrgID:         orgID,
		ServesInbound: canServeInbound(leaf) && len(leaf.DNSNames)+len(leaf.IPAddresses) > 0,
	}, nil
}

// canServeInbound mirrors crypto/x509's own rule for "may this certificate be a
// TLS server's", because the party that decides is the CLIENT verifying it, and
// that is the rule the client applies (verify.go, checkChainForKeyUsage).
//
// Being stricter here than the client is not the safe direction: it would leave
// a node whose certificate works perfectly well falling back to a self-signed
// one, which every device then refuses. So an ABSENT extension reads as
// unconstrained, exactly as it does there, and anyExtendedKeyUsage counts.
func canServeInbound(leaf *x509.Certificate) bool {
	if len(leaf.ExtKeyUsage) == 0 && len(leaf.UnknownExtKeyUsage) == 0 {
		return true
	}
	for _, u := range leaf.ExtKeyUsage {
		if u == x509.ExtKeyUsageServerAuth || u == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

// FromFile reads a PEM certificate file and returns the identity of its LEAF —
// the first CERTIFICATE block, which is where crypto/tls also expects the leaf
// when the file holds a chain.
//
// This is how a node learns its own identity: it reads back the same file it
// presents to bff-edge, so what it believes about itself and what the control
// plane authenticates it as come from one source.
func FromFile(certPath string) (Identity, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return Identity{}, fmt.Errorf("edgecert: read %q: %w", certPath, err)
	}
	id, err := FromPEM(data)
	if err != nil {
		return Identity{}, fmt.Errorf("%w (%s)", err, certPath)
	}
	return id, nil
}

// FromPEM is FromFile over bytes already in hand. Callers that must tell a
// file they could not READ (not their machine, not their business) from one
// they read and could not PARSE (a real misconfiguration) do the read
// themselves and come here — the two deserve different answers.
func FromPEM(data []byte) (Identity, error) {
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		if block.Type != "CERTIFICATE" {
			continue
		}
		leaf, perr := x509.ParseCertificate(block.Bytes)
		if perr != nil {
			return Identity{}, fmt.Errorf("edgecert: parse leaf: %w", perr)
		}
		return FromLeaf(leaf)
	}
	return Identity{}, fmt.Errorf("edgecert: no CERTIFICATE block")
}
