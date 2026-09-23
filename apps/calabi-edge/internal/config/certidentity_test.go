package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/calabinet/calabi/pkg/edgecert"
)

// A node wired to a control plane takes its identity from its own mTLS
// certificate, because that is the copy the control plane authenticates it by.
// See certidentity.go for why the file could never be the answer.

// loadWithCert writes a certificate + a config that points at it, and runs the
// real boot pipeline over the pair. certCN empty writes no certificate file at
// all, so the config can name a path that is not there.
func loadWithCert(t *testing.T, certCN string, sans []*url.URL, body string) (Config, Notes, error) {
	t.Helper()
	clearCalabiEnv(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "edge-client.crt")
	if certCN != "" {
		writeCert(t, certPath, certCN, sans)
	}
	cfgPath := filepath.Join(dir, "edge.yaml")
	full := body + fmt.Sprintf(`
public:
  host: edge.example
multi_region:
  mode: bff-edge
  bff_edge_addr: bff-edge.example:443
  client_cert: %s
  client_key: %s
  ca: %s
`, certPath, filepath.Join(dir, "edge-client.key"), filepath.Join(dir, "ca.crt"))
	if err := os.WriteFile(cfgPath, []byte(full), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, notes, err := LoadEffective(cfgPath)
	return cfg, notes, err
}

func TestIdentityComesFromTheCertificate(t *testing.T) {
	// The file says nothing about who this node is. Everything below came out
	// of the certificate.
	cfg, notes, err := loadWithCert(t, edgecert.CommonName(104, "ap-singapore"), nil,
		"node_label: sgp-01\nbase_domain: sgp.calabi.online\naccepted_tokens: []\n")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.EdgeNodeID != 104 {
		t.Errorf("edge_node_id = %d, want 104 from the cert CN", cfg.EdgeNodeID)
	}
	if cfg.Region != "ap-singapore" {
		t.Errorf("region = %q, want ap-singapore from the cert CN", cfg.Region)
	}
	for _, w := range notes.Warnings {
		t.Errorf("unexpected warning for a config that names neither: %s", w)
	}
}

func TestBYOIOrgComesFromTheCertificate(t *testing.T) {
	const id = 1000400000
	cfg, _, err := loadWithCert(t, edgecert.CommonName(id, "cn-chengdu"),
		[]*url.URL{edgecert.SPIFFEURI(42, id, "cn-chengdu")},
		"node_label: team-vps-01\nbase_domain: t.example\naccepted_tokens: []\n")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.OrgID != 42 {
		t.Errorf("org_id = %d, want 42 from the cert's SPIFFE SAN", cfg.OrgID)
	}
	if cfg.EdgeNodeID != id {
		t.Errorf("edge_node_id = %d, want %d", cfg.EdgeNodeID, int64(id))
	}
}

// A PLATFORM certificate carries no org, and the ZERO that leaves here means
// EVERY org — a platform node terminates TLS for all of them — not "unknown".
//
// bff-edge reads the same absence from the same certificate and turns it into
// an all-org cert listing, so nothing downstream has to guess. Before that
// existed, zero meant neither: cert-svc rejects org_id <= 0, so a platform node
// named one org in its config and served only that org's certificates, while
// everyone else's arrived by push and were wiped by the next reconcile.
func TestPlatformCertMeansEveryOrg(t *testing.T) {
	cfg, _, err := loadWithCert(t, edgecert.CommonName(104, "ap-singapore"), nil,
		"node_label: sgp-01\nbase_domain: sgp.calabi.online\naccepted_tokens: []\n")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.OrgID != 0 {
		t.Fatalf("org_id = %d, want 0 — a platform certificate names no org because the node serves them all", cfg.OrgID)
	}
}

func TestConfigAgreeingWithTheCertificateSaysTheLineCanGo(t *testing.T) {
	const id = 1000400000
	cfg, notes, err := loadWithCert(t, edgecert.CommonName(id, "cn-chengdu"),
		[]*url.URL{edgecert.SPIFFEURI(42, id, "cn-chengdu")},
		fmt.Sprintf("node_label: team-vps-01\nregion: cn-chengdu\nedge_node_id: %d\n"+
			"base_domain: t.example\naccepted_tokens: []\n", id))
	if err != nil {
		t.Fatalf("a config that agrees with its certificate must load: %v", err)
	}
	if cfg.EdgeNodeID != id || cfg.Region != "cn-chengdu" || cfg.OrgID != 42 {
		t.Errorf("got id=%d region=%q org=%d", cfg.EdgeNodeID, cfg.Region, cfg.OrgID)
	}
	// One line per setting the certificate already answers, so an operator
	// upgrading learns what to delete without reading a changelog. (org_id is
	// not among them: the file cannot spell it at all any more — layout.go
	// refuses it, and TestRemovedKnobsAreRefused pins that.)
	for _, want := range []string{"edge_node_id", "region"} {
		if !anyContains(notes.Warnings, want) {
			t.Errorf("no warning mentions %s; got %q", want, notes.Warnings)
		}
	}
}

// The whole point of the change: a disagreement is an error at boot, not a node
// that runs under an identity nobody else uses for it.
func TestConfigDisagreeingWithTheCertificateIsRefused(t *testing.T) {
	const id = 1000400000
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "edge_node_id",
			body: "node_label: a\nregion: cn-chengdu\nedge_node_id: 7\naccepted_tokens: []\n",
			want: "edge_node_id",
		},
		{
			name: "region",
			body: "node_label: a\nregion: us-losangeles\naccepted_tokens: []\n",
			want: "region",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _, err := loadWithCert(t, edgecert.CommonName(id, "cn-chengdu"),
				[]*url.URL{edgecert.SPIFFEURI(42, id, "cn-chengdu")}, tc.body)
			if err == nil {
				t.Fatalf("want a refusal, got id=%d region=%q org=%d", cfg.EdgeNodeID, cfg.Region, cfg.OrgID)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error does not name %s: %v", tc.want, err)
			}
		})
	}
}

// Region case is a difference in spelling, not in meaning, and the config's
// spelling wins: a platform relay advertises its DERP region under this exact
// string, so re-casing it here would move the relay in the map.
func TestRegionCaseDisagreementIsNotADisagreement(t *testing.T) {
	cfg, _, err := loadWithCert(t, edgecert.CommonName(104, "ap-singapore"), nil,
		"node_label: sgp-01\nregion: AP-Singapore\naccepted_tokens: []\n")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Region != "AP-Singapore" {
		t.Errorf("region = %q, want the config's own spelling kept", cfg.Region)
	}
}

// This same pipeline runs in tests, in the deployed-config checks, and wherever
// someone opens an edge.yaml on a machine that is not that edge. None of them
// hold the node's private material, and none of them should fail for it.
func TestACertificateWeCannotReadIsNotAnError(t *testing.T) {
	cfg, notes, err := loadWithCert(t, "", nil,
		"node_label: sgp-01\nregion: ap-singapore\nedge_node_id: 104\naccepted_tokens: []\n")
	if err != nil {
		t.Fatalf("a config whose cert is not on this machine must still load: %v", err)
	}
	if cfg.EdgeNodeID != 104 {
		t.Errorf("edge_node_id = %d, want the config's 104 kept when the cert cannot be read", cfg.EdgeNodeID)
	}
	if !anyContains(notes.Warnings, "NOT verified") {
		t.Errorf("an unverified identity must say so; got %q", notes.Warnings)
	}
}

// A file we CAN read and cannot parse is the other case, and it is fatal:
// something is wrong with this node's certificate and the dial is about to fail
// anyway, so say which file and why.
func TestACertificateWeCanReadAndCannotParseIsFatal(t *testing.T) {
	dir := t.TempDir()
	clearCalabiEnv(t)
	certPath := filepath.Join(dir, "edge-client.crt")
	if err := os.WriteFile(certPath, []byte("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "edge.yaml")
	body := fmt.Sprintf("node_label: a\naccepted_tokens: []\npublic:\n  host: a.example\n"+
		"multi_region:\n  mode: bff-edge\n  client_cert: %s\n", certPath)
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadEffective(cfgPath); err == nil {
		t.Fatal("want a refusal for a client_cert that is not a certificate")
	}
}

// Not every edge has a control plane. A self-hosted one has no certificate, and
// nothing anywhere is keyed on its id, so nothing here touches it.
func TestStandaloneNodeIsLeftAlone(t *testing.T) {
	clearCalabiEnv(t)
	p := filepath.Join(t.TempDir(), "edge.yaml")
	body := "node_label: home\nregion: home-lan\nmode: standalone\ncoord_pubkey: " + testCoordKey +
		"\npublic:\n  host: home.example\naccepted_tokens: []\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, notes, err := LoadEffective(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Region != "home-lan" || cfg.EdgeNodeID != 0 {
		t.Errorf("got region=%q id=%d, want the file's own values untouched", cfg.Region, cfg.EdgeNodeID)
	}
	for _, w := range notes.Warnings {
		t.Errorf("a node with no control plane has nothing to verify against: %s", w)
	}
}

// The hot-reloader diffs a fresh LoadEffective against the one boot produced
// and refuses any field that moved. An identity resolved OUTSIDE this pipeline
// would differ on every reload and refuse them all — this is the property that
// says it is inside.
func TestTwoLoadsOfOneFileAgree(t *testing.T) {
	clearCalabiEnv(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "edge-client.crt")
	writeCert(t, certPath, edgecert.CommonName(104, "ap-singapore"), nil)
	cfgPath := filepath.Join(dir, "edge.yaml")
	body := fmt.Sprintf("node_label: sgp-01\nbase_domain: sgp.calabi.online\naccepted_tokens: []\n"+
		"public:\n  host: edge01-sgp.calabi.net\n"+
		"multi_region:\n  mode: bff-edge\n  client_cert: %s\n", certPath)
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	first, _, err := LoadEffective(cfgPath)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	second, _, err := LoadEffective(cfgPath)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("two loads of one file differ:\n first=%+v\nsecond=%+v", first, second)
	}
}

// ---------- helpers ----------

func anyContains(lines []string, want string) bool {
	for _, l := range lines {
		if strings.Contains(l, want) {
			return true
		}
	}
	return false
}

func writeCert(t *testing.T, path, cn string, uris []*url.URL) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         uris,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A BYOI node's leaf does both jobs: it authenticates the node TO the control
// plane and it is what devices verify when they dial its control listener.
// cert-svc mints it that way (serverAuth EKU + the node's public address), so
// naming the path twice only created somewhere for the two to disagree.
func TestBYOICertAlsoServesTheControlListener(t *testing.T) {
	const id = 1000400000
	dir := t.TempDir()
	certPath := filepath.Join(dir, "edge-tls.crt")
	keyPath := filepath.Join(dir, "edge-tls.key")
	writeServingCert(t, certPath, edgecert.CommonName(id, "cn-chengdu"),
		[]*url.URL{edgecert.SPIFFEURI(42, id, "cn-chengdu")}, "edge.customer.example")
	cfgPath := filepath.Join(dir, "edge.yaml")
	body := fmt.Sprintf("node_label: team-vps-01\nbase_domain: t.example\naccepted_tokens: []\n"+
		"public:\n  host: edge.customer.example\n"+
		"multi_region:\n  mode: bff-edge\n  client_cert: %s\n  client_key: %s\n", certPath, keyPath)
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	clearCalabiEnv(t)
	cfg, notes, err := LoadEffective(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Tunnel.ControlCertPEM != certPath || cfg.Tunnel.ControlKeyPEM != keyPath {
		t.Fatalf("control listener got (%q, %q), want this node's own certificate",
			cfg.Tunnel.ControlCertPEM, cfg.Tunnel.ControlKeyPEM)
	}
	if !anyContains(notes.Warnings, certPath) {
		t.Errorf("a listener certificate the file does not name should be logged; notes = %q", notes.Warnings)
	}
}

// A PLATFORM node's client leaf is client-only, and a Go TLS server does not
// check the EKU of what it serves — the client does. Installing it on the
// listener would start cleanly and fail at every device, so the inheritance is
// gated on the certificate saying it can, not on the config's shape.
func TestAClientOnlyCertIsNotPutOnTheListener(t *testing.T) {
	cfg, _, err := loadWithCert(t, edgecert.CommonName(104, "ap-singapore"), nil,
		"node_label: sgp-01\nbase_domain: sgp.calabi.online\naccepted_tokens: []\n")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Tunnel.ControlCertPEM != "" {
		t.Fatalf("control.cert_pem = %q, want empty: this leaf carries no serverAuth EKU",
			cfg.Tunnel.ControlCertPEM)
	}
}

// An explicit control.cert_pem still wins — the inheritance only fills a blank.
func TestAnExplicitControlCertIsKept(t *testing.T) {
	const id = 1000400000
	dir := t.TempDir()
	certPath := filepath.Join(dir, "edge-tls.crt")
	keyPath := filepath.Join(dir, "edge-tls.key")
	writeServingCert(t, certPath, edgecert.CommonName(id, "cn-chengdu"),
		[]*url.URL{edgecert.SPIFFEURI(42, id, "cn-chengdu")}, "edge.customer.example")
	cfgPath := filepath.Join(dir, "edge.yaml")
	body := fmt.Sprintf("node_label: team-vps-01\naccepted_tokens: []\n"+
		"public:\n  host: edge.customer.example\n"+
		"tunnel:\n  base_domain: t.example\n"+
		"  control_cert_pem: /etc/calabi/own.crt\n  control_key_pem: /etc/calabi/own.key\n"+
		"multi_region:\n  mode: bff-edge\n  client_cert: %s\n  client_key: %s\n", certPath, keyPath)
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	clearCalabiEnv(t)
	cfg, _, err := LoadEffective(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Tunnel.ControlCertPEM != "/etc/calabi/own.crt" {
		t.Errorf("control.cert_pem = %q, want the operator's own", cfg.Tunnel.ControlCertPEM)
	}
}

// writeServingCert writes a leaf that can do both jobs, plus its key.
func writeServingCert(t *testing.T, certPath, cn string, uris []*url.URL, dnsName string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         uris,
		DNSNames:     []string{dnsName},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := certPath[:len(certPath)-len(".crt")] + ".key"
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The deploy risk this change introduces, made loud. A BYOI node whose files no
// longer name a control certificate, and whose own certificate cannot serve one
// (issued before its public address was known), falls back to a self-signed
// certificate — which every device verifying against the Calabi edge CA refuses.
// Silent, and indistinguishable at the node from working.
func TestABYOINodeWithNothingToServeSaysSo(t *testing.T) {
	const id = 1000400000
	cfg, notes, err := loadWithCert(t, edgecert.CommonName(id, "cn-chengdu"),
		[]*url.URL{edgecert.SPIFFEURI(42, id, "cn-chengdu")},
		"node_label: team-vps-01\nbase_domain: t.example\naccepted_tokens: []\n")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Tunnel.ControlCertPEM != "" {
		t.Fatalf("a client-only certificate was put on the listener: %q", cfg.Tunnel.ControlCertPEM)
	}
	if !anyContains(notes.Warnings, "self-signed") {
		t.Errorf("the fallback to self-signed must be stated; got %q", notes.Warnings)
	}
}
