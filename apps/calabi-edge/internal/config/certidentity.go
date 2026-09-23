package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/calabinet/calabi/pkg/edgecert"
)

// resolveCertIdentity settles who this node IS from the one source both ends
// already agree on: its own mTLS client certificate.
//
// # WHY THE FILE CANNOT BE THE ANSWER
//
// bff-edge does not believe a word of what an edge says about its own identity.
// Its auth interceptor reads (edge_node_id, region, org_id) out of the client
// cert and OVERWRITES those fields on every inbound RPC — deliberately, so a
// leaked cert for edge 42 cannot report as edge 7 by editing a request body
// (apps/bff-edge/internal/server: "Region from cert wins over body too —
// operators pin the region in cert issuance and the edge shouldn't be able to
// relocate itself by editing its YAML").
//
// So the numbers in edge.yaml never reached the control plane. What they did
// reach is THIS process: the id is what the config-svc route filter compares
// against, what the mesh resolver calls "mine", what the session-evict NATS
// subject is keyed on, and what the port-claim seed asks for. Every one of
// those compares against control-plane data stamped from the CERT. The file's
// only job was to agree with the certificate, and nothing anywhere checked that
// it did — deploy/compose/edge/sgp-01/config.yaml states the rule in a comment
// ("Local self-id MUST equal the numeric id in this edge's mTLS cert CN") and a
// comment is not a check. Get it wrong and the node boots clean, serves nobody's
// tunnels as its own, and never says why.
//
// Now it is read, not written. What the file still holds is CHECKED against the
// certificate, and a disagreement refuses the boot — which turns the silent
// split-brain above into a first-second error message.
//
// # WHEN THE CERT IS NOT HERE
//
// Only a bff-edge node has one. A self-hosted / standalone edge has no control
// plane, nothing on the far end keyed by its id, and no cert to read, so this
// leaves it alone entirely.
//
// A cert path we cannot READ is also left alone, without an error: this same
// pipeline runs in tests, in the deployed-config checks, and anywhere someone
// inspects an edge.yaml on a machine that is not that edge. The real box does
// have the file — bffedgeclient.Dial needs the identical path and refuses to
// start without it — so skipping here costs nothing there. A file we CAN read
// and cannot parse is a different matter and is fatal.
//
// raw is the file over a ZERO Config (loadWithRaw), and the comparisons below
// read IT, not cfg: "what the operator wrote" is the only thing worth checking
// against the certificate. Reading cfg instead refuses every platform edge,
// because Default() fills region with "local" and no certificate says that.
func resolveCertIdentity(cfg *Config, raw Config) ([]string, error) {
	if !cfg.MultiRegion.IsBFFEdge() {
		return nil, nil
	}
	path := strings.TrimSpace(cfg.MultiRegion.ClientCert)
	if path == "" {
		return []string{"multi_region.mode is bff-edge but multi_region.client_cert is empty: " +
			"this node's identity could not be read from its certificate (and the bff-edge dial will fail)"}, nil
	}
	certPEM, err := os.ReadFile(path)
	if err != nil {
		return []string{fmt.Sprintf("could not read multi_region.client_cert (%v): "+
			"this node's identity was taken from the config file and NOT verified against its certificate", err)}, nil
	}
	id, err := edgecert.FromPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("multi_region.client_cert %q is not an edge certificate: %w", path, err)
	}

	var notes []string
	note := func(format string, args ...any) { notes = append(notes, fmt.Sprintf(format, args...)) }

	// edge_node_id — always the cert's.
	switch {
	case raw.EdgeNodeID == 0:
	case raw.EdgeNodeID == id.EdgeNodeID:
		note("edge_node_id: %d is what this node's certificate already says; the line can be deleted", id.EdgeNodeID)
	default:
		return nil, fmt.Errorf("edge_node_id: the config says %d, this node's certificate says %d. "+
			"The control plane goes by the certificate, so the config value would only ever split this "+
			"node's local view from the control plane's. Delete the line (or reissue the certificate)",
			raw.EdgeNodeID, id.EdgeNodeID)
	}
	cfg.EdgeNodeID = id.EdgeNodeID

	// region — same story (RegisterEdgeNode takes the cert's), but the config
	// spelling is KEPT when the two agree. Region strings reach further than the
	// control plane: a platform relay advertises its DERP region under this
	// exact string, so quietly re-casing it here would move the relay in the map.
	switch {
	case strings.TrimSpace(raw.Region) == "":
		cfg.Region = id.Region
	case strings.EqualFold(strings.TrimSpace(raw.Region), id.Region):
		note("region: %q is what this node's certificate already says; the line can be deleted", id.Region)
	default:
		return nil, fmt.Errorf("region: the config says %q, this node's certificate says %q. "+
			"The control plane registers this node under the certificate's region, so the two would "+
			"disagree about where it is. Delete the line (or reissue the certificate)",
			strings.TrimSpace(raw.Region), id.Region)
	}

	// org_id — no cross-check, because the file cannot spell it any more
	// (layout.go refuses both `org_id` and the older `cert.org_id`).
	//
	// A BYOI certificate names one org and that is this node's. A PLATFORM
	// certificate names none, and the ZERO left here means "every org", not
	// "unknown": bff-edge reads the same absence and asks cert-svc for an
	// all-org cert listing. It used to mean neither — cert-svc rejects
	// org_id <= 0, so a platform node had to name a single org in its config
	// and then served only that org's certificates, with everybody else's
	// arriving by push event and being wiped by the next reconcile.
	cfg.OrgID = id.OrgID

	// One certificate, named once.
	//
	// A BYOI node's leaf is minted to do both jobs — client credential to the
	// control plane, server credential to the devices dialing its control
	// listener. Both deployed
	// BYOI configs therefore wrote the same path twice, and nothing tied the two
	// together: re-issue to a new path, update one line, and the listener keeps
	// serving the old file until somebody notices devices cannot connect.
	//
	// Gated on ServesInbound, which is read off the certificate rather than
	// guessed from the config, because the failure is REMOTE. A Go TLS server
	// does not check the EKU of what it serves — the client does — so putting a
	// client-only leaf on the listener starts cleanly and fails at every device.
	// A platform node's client leaf is client-only, so this never fires there,
	// and it names its own server certificate anyway.
	blank := strings.TrimSpace(raw.Tunnel.ControlCertPEM) == "" && strings.TrimSpace(raw.Tunnel.ControlKeyPEM) == ""
	switch {
	case !cfg.ServesTunnels():
	case !id.ServesInbound && blank && id.OrgID > 0:
		// Nothing to inherit and nothing configured, on a node whose devices
		// verify its listener against the edge CA baked into their binary. The
		// listener will fall back to a self-signed certificate and every one of
		// them will refuse it. Say so at boot rather than leaving it to a
		// support ticket — the fix is to re-issue this node's certificate with
		// its public address, which is what makes it serve inbound too.
		note("control listener: no certificate configured, and this node's own cannot serve one " +
			"(no serverAuth extension, or no name for its public address) — it will present a self-signed " +
			"certificate that devices verifying against the Calabi edge CA will refuse. Re-issue this " +
			"node's certificate with its public address, or set tunnel.control_cert_pem / control_key_pem")
	case !id.ServesInbound:
	case blank:
		if key := strings.TrimSpace(cfg.MultiRegion.ClientKey); key != "" {
			cfg.Tunnel.ControlCertPEM, cfg.Tunnel.ControlKeyPEM = path, key
			note("control listener: serving this node's own certificate (%s), the one it authenticates to the control plane with", path)
		}
	case strings.TrimSpace(raw.Tunnel.ControlCertPEM) == path:
		note("control_cert_pem names the same file as multi_region.client_cert; the lines can be deleted and the edge will use it anyway")
	}
	return notes, nil
}
