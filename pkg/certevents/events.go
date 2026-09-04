// Package certevents declares the NATS subjects and payload shapes
// cert-svc publishes after a cert mutation. Edge-nodes subscribe to
// these so they can keep their in-process tls.Certificate pool
// current without 30s full-catalog polling.
//
// SUBJECT LAYOUT
// --------------
// Subjects are hierarchical so edges can wildcard-subscribe to all
// orgs they serve:
//
//	calabi.cert.upsert.<org_id>   — a cert was created or replaced
//	calabi.cert.delete.<org_id>   — a cert was soft-deleted
//
// Edge usually subscribes to "calabi.cert.upsert.>" and
// "calabi.cert.delete.>" because- it serves all orgs anyway;
// org-scoped subscription becomes interesting when we partition
// edges by tenant.
//
// PAYLOAD
// -------
// Bodies are tiny JSON with just enough for the edge to decide which
// cert to refetch. The actual PEM + decrypted private key still comes
// down via the GetCert RPC — so private keys never traverse NATS.
//
// FAILURE MODES
// -------------
// NATS delivery is at-most-once for plain subjects. The edge keeps a
// loose 5-minute refresh poll as a fallback so a dropped message is
// reconciled within one TTL window.
//
// PACKAGE LOCATION
// ----------------
// Lives under pkg/ (not apps/cert-svc/internal/) because calabi-edge
// consumes the same constants on the subscribe side. Keeping one
// canonical declaration avoids the cross-svc drift seen between
// usage.SubjectReport and consumer.SubjectUsageReport.
package certevents

import "fmt"

// SubjectUpsertPrefix is the parent of all upsert subjects. Edges
// subscribe with "calabi.cert.upsert.>".
const SubjectUpsertPrefix = "calabi.cert.upsert."

// SubjectDeletePrefix is the parent of all delete subjects.
const SubjectDeletePrefix = "calabi.cert.delete."

// ACME HTTP-01 challenge fan-out.
//
// When cert-svc drives an http-01 issuance for a user's custom domain,
// lego calls the challenge provider's Present()/CleanUp(). The token +
// keyAuth live only in cert-svc memory, but Let's Encrypt validates by
// fetching http://<domain>/.well-known/acme-challenge/<token> — which
// lands on an calabi-edge (a SEPARATE process). So cert-svc broadcasts
// the (token,keyAuth) over NATS; every edge caches it and the visitor
// HTTP listener answers the challenge before host routing.
//
// These are NOT org-scoped: the validation request is anonymous HTTP and
// any edge fronting the domain must be able to answer it, regardless of
// which org owns the cert. Broadcasting to all edges also sidesteps the
// "which cert-svc replica holds the token" problem (any edge can serve).
//
// Payload is ChallengeEvent JSON. Tokens are public by design (the
// keyAuth only proves control to an ACME server that already issued the
// token), so no secret traverses NATS here.
const (
	// SubjectACMEChallengePresent carries a token to install. Edges
	// subscribe to this exact subject.
	SubjectACMEChallengePresent = "calabi.acme.challenge.present"
	// SubjectACMEChallengeCleanup carries a token to drop after the
	// validation finished (success or failure).
	SubjectACMEChallengeCleanup = "calabi.acme.challenge.cleanup"
)

// UpsertSubject formats the concrete subject for a given org.
func UpsertSubject(orgID int64) string {
	return fmt.Sprintf("%s%d", SubjectUpsertPrefix, orgID)
}

// DeleteSubject formats the concrete subject for a given org.
func DeleteSubject(orgID int64) string {
	return fmt.Sprintf("%s%d", SubjectDeletePrefix, orgID)
}

// CertEvent is the JSON body of both upsert and delete messages.
//
// Fields:
//   - CertID:      primary key in cert-svc; edge uses this with GetCert(id)
//   - OrgID:       redundant with the subject; included for log/UI clarity
//   - SANs:        all the SNI hostnames this cert covers — lets the edge
//     drop stale entries from the pool on upsert (e.g. when
//     a re-issued cert no longer covers an old SAN) without
//     a second round trip
//   - Subject:     legacy CN, only used when SANs is empty (single-name
//     certs from manual upload)
//   - Fingerprint: SHA256 of the leaf DER; lets the edge skip the GetCert
//     refetch if it already has this exact bytes (e.g. the
//     same publish was re-delivered)
//
// Note: NO PEM, NO PRIVATE KEY. The edge fetches those via GetCert RPC
// after deciding to react to this event.
type CertEvent struct {
	CertID      int64    `json:"cert_id"`
	OrgID       int64    `json:"org_id"`
	SANs        []string `json:"sans,omitempty"`
	Subject     string   `json:"subject,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
}

// ChallengeEvent is the JSON body of the ACME http-01 present/cleanup
// messages. On present, KeyAuth is the value the edge must return at
// /.well-known/acme-challenge/<Token>. On cleanup, only Token matters.
// Domain is carried for log clarity only.
type ChallengeEvent struct {
	Token   string `json:"token"`
	KeyAuth string `json:"key_auth,omitempty"`
	Domain  string `json:"domain,omitempty"`
}
