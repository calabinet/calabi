package edgecert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseCommonName(t *testing.T) {
	cases := []struct {
		name       string
		cn         string
		wantID     int64
		wantRegion string
		wantErr    bool
	}{
		{name: "happy/simple", cn: "edge-1-cn-chengdu", wantID: 1, wantRegion: "cn-chengdu"},
		{name: "happy/larger-id", cn: "edge-4242-ap-singapore", wantID: 4242, wantRegion: "ap-singapore"},
		{name: "missing prefix", cn: "node-1-cn-chengdu", wantErr: true},
		{name: "empty CN", cn: "", wantErr: true},
		{name: "no region", cn: "edge-42", wantErr: true},
		{name: "non-numeric id", cn: "edge-x-cn-chengdu", wantErr: true},
		{name: "zero id", cn: "edge-0-cn-chengdu", wantErr: true},
		{name: "trailing dash, empty region", cn: "edge-42-", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, region, err := ParseCommonName(tc.cn)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got id=%d region=%q", id, region)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if id != tc.wantID {
				t.Errorf("id: got %d, want %d", id, tc.wantID)
			}
			if region != tc.wantRegion {
				t.Errorf("region: got %q, want %q", region, tc.wantRegion)
			}
		})
	}
}

func TestParseOrgSAN(t *testing.T) {
	cases := []struct {
		name     string
		uris     []*url.URL
		wantOrg  int64
		wantEdge int64
		wantErr  bool
	}{
		{name: "byoi/happy", uris: []*url.URL{mustURL(t, "spiffe://calabi/org/7/edge/42/region/cn-chengdu")}, wantOrg: 7, wantEdge: 42},
		{name: "byoi/region with dashes", uris: []*url.URL{mustURL(t, "spiffe://calabi/org/100/edge/9/region/ap-southeast-1")}, wantOrg: 100, wantEdge: 9},
		{name: "platform/no SAN", uris: nil, wantOrg: 0, wantEdge: 0},
		{name: "platform/foreign trust domain skipped", uris: []*url.URL{mustURL(t, "spiffe://other/org/7/edge/42")}, wantOrg: 0, wantEdge: 0},
		{name: "platform/non-spiffe scheme skipped", uris: []*url.URL{mustURL(t, "https://calabi/org/7/edge/42")}, wantOrg: 0, wantEdge: 0},
		{name: "bad/org zero", uris: []*url.URL{mustURL(t, "spiffe://calabi/org/0/edge/42/region/x")}, wantErr: true},
		{name: "bad/org non-numeric", uris: []*url.URL{mustURL(t, "spiffe://calabi/org/abc/edge/42/region/x")}, wantErr: true},
		{name: "bad/edge zero", uris: []*url.URL{mustURL(t, "spiffe://calabi/org/7/edge/0/region/x")}, wantErr: true},
		{name: "bad/wrong path shape", uris: []*url.URL{mustURL(t, "spiffe://calabi/foo/7/bar/42")}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			org, edge, err := ParseOrgSAN(tc.uris)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got org=%d edge=%d", org, edge)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if org != tc.wantOrg {
				t.Errorf("org: got %d, want %d", org, tc.wantOrg)
			}
			if edge != tc.wantEdge {
				t.Errorf("edge: got %d, want %d", edge, tc.wantEdge)
			}
		})
	}
}

// TestWhatWeWriteIsWhatWeRead is the reason the formatter lives in this package
// next to the parser. cert-svc writes the CN and the SAN; bff-edge and the edge
// itself read them back. Before this package those were three independent
// string literals in three modules, and nothing anywhere compared them.
//
// Region strings are deliberately awkward: hyphens are the separator the CN
// parser has to scan past, and a region that is itself a number would break a
// parser that split from the right.
func TestWhatWeWriteIsWhatWeRead(t *testing.T) {
	regions := []string{"local", "cn-chengdu", "ap-southeast-1", "us-west-2-lax", "1"}
	ids := []int64{1, 7, 104, 1000300003}
	orgs := []int64{1, 42, 1000}

	for _, region := range regions {
		for _, id := range ids {
			gotID, gotRegion, err := ParseCommonName(CommonName(id, region))
			if err != nil {
				t.Fatalf("CommonName(%d, %q) does not parse: %v", id, region, err)
			}
			if gotID != id || gotRegion != region {
				t.Errorf("CN round trip for (%d, %q): got (%d, %q)", id, region, gotID, gotRegion)
			}
			for _, org := range orgs {
				uri := SPIFFEURI(org, id, region)
				gotOrg, gotEdge, serr := ParseOrgSAN([]*url.URL{uri})
				if serr != nil {
					t.Fatalf("SPIFFEURI(%d, %d, %q) = %q does not parse: %v", org, id, region, uri, serr)
				}
				if gotOrg != org || gotEdge != id {
					t.Errorf("SAN round trip for (%d, %d, %q): got (%d, %d)", org, id, region, gotOrg, gotEdge)
				}
			}
		}
	}
}

func TestFromLeaf(t *testing.T) {
	t.Run("platform edge has no org", func(t *testing.T) {
		leaf := leafFor(t, CommonName(104, "ap-singapore"), nil)
		got, err := FromLeaf(leaf)
		if err != nil {
			t.Fatalf("FromLeaf: %v", err)
		}
		want := Identity{EdgeNodeID: 104, Region: "ap-singapore", OrgID: 0}
		if got != want {
			t.Fatalf("got %+v, want %+v", got, want)
		}
		if !got.IsPlatform() {
			t.Error("IsPlatform() = false for a cert with no org SAN")
		}
	})

	t.Run("byoi edge carries its org", func(t *testing.T) {
		leaf := leafFor(t, CommonName(1000400000, "cn-chengdu"),
			[]*url.URL{SPIFFEURI(42, 1000400000, "cn-chengdu")})
		got, err := FromLeaf(leaf)
		if err != nil {
			t.Fatalf("FromLeaf: %v", err)
		}
		want := Identity{EdgeNodeID: 1000400000, Region: "cn-chengdu", OrgID: 42}
		if got != want {
			t.Fatalf("got %+v, want %+v", got, want)
		}
		if got.IsPlatform() {
			t.Error("IsPlatform() = true for a cert with an org SAN")
		}
	})

	// The cross-field rule: without it a cert could present CN edge-7 while its
	// SAN claimed org 42's edge-42, and the two readers of this cert would
	// disagree about which node it is.
	t.Run("SAN naming another edge is refused", func(t *testing.T) {
		leaf := leafFor(t, CommonName(7, "cn-chengdu"),
			[]*url.URL{SPIFFEURI(42, 4242, "cn-chengdu")})
		if got, err := FromLeaf(leaf); err == nil {
			t.Fatalf("want error, got %+v", got)
		}
	})

	t.Run("nil", func(t *testing.T) {
		if _, err := FromLeaf(nil); err == nil {
			t.Fatal("want error for a nil certificate")
		}
	})
}

func TestFromFile(t *testing.T) {
	dir := t.TempDir()

	t.Run("reads the leaf of a chain", func(t *testing.T) {
		leaf := leafFor(t, CommonName(104, "ap-singapore"), nil)
		other := leafFor(t, CommonName(999, "somewhere-else"), nil)
		// Leaf FIRST, then a second cert standing in for an intermediate: the
		// order crypto/tls assumes, and the one that decides which identity a
		// chain file reports.
		path := filepath.Join(dir, "chain.pem")
		writePEM(t, path, leaf, other)

		got, err := FromFile(path)
		if err != nil {
			t.Fatalf("FromFile: %v", err)
		}
		if got.EdgeNodeID != 104 {
			t.Errorf("got edge id %d, want the FIRST block's 104", got.EdgeNodeID)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		if _, err := FromFile(filepath.Join(dir, "nope.pem")); err == nil {
			t.Fatal("want error for a missing file")
		}
	})

	t.Run("not a certificate", func(t *testing.T) {
		path := filepath.Join(dir, "key.pem")
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{
			Type: "PRIVATE KEY", Bytes: []byte("not a cert"),
		}), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := FromFile(path); err == nil {
			t.Fatal("want error for a PEM file with no CERTIFICATE block")
		}
	})
}

func TestHasOrgSAN(t *testing.T) {
	cases := []struct {
		name string
		uris []*url.URL
		want bool
	}{
		{name: "none", uris: nil, want: false},
		{name: "org san", uris: []*url.URL{SPIFFEURI(7, 42, "x")}, want: true},
		{name: "other scheme", uris: []*url.URL{mustURL(t, "https://calabi/org/7/edge/42")}, want: false},
		// Looser than ParseOrgSAN on purpose — see the doc comment. Somebody
		// meant to pin this cert; reading it as a platform cert is the unsafe
		// direction.
		{name: "unparseable spiffe still counts", uris: []*url.URL{mustURL(t, "spiffe://calabi/nonsense")}, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasOrgSAN(tc.uris); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// ---------- helpers ----------

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return u
}

// leafFor self-signs a certificate carrying the given CN and URI SANs. The key
// is 1024-bit because nothing here verifies a signature and 2048 makes the
// table tests noticeably slow.
func leafFor(t *testing.T, cn string, uris []*url.URL) *x509.Certificate {
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
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func writePEM(t *testing.T, path string, certs ...*x509.Certificate) {
	t.Helper()
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

// ServesInbound decides whether one certificate can be both a node's client
// credential to the control plane and its server credential to devices. Getting
// it wrong fails REMOTELY — a Go TLS server does not check the EKU of what it
// serves, the client does — so it is read off the certificate rather than
// inferred from the config.
func TestServesInbound(t *testing.T) {
	cases := []struct {
		name string
		tune func(*x509.Certificate)
		want bool
	}{
		{
			name: "BYOI leaf with serverAuth and a name",
			tune: func(c *x509.Certificate) {
				c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
				c.DNSNames = []string{"edge.customer.example"}
			},
			want: true,
		},
		{
			name: "IP instead of a DNS name",
			tune: func(c *x509.Certificate) {
				c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
				c.IPAddresses = []net.IP{net.ParseIP("203.0.113.9")}
			},
			want: true,
		},
		{
			// No EKU extension at all is UNCONSTRAINED in X.509, and crypto/x509
			// reads it that way (verify.go: "The certificate doesn't have any
			// extended key usage specified" → skip the cert). Being stricter
			// here than the client that verifies us is not the safe direction:
			// it would leave a node whose certificate works perfectly well
			// falling back to a self-signed one that every device refuses.
			name: "no EKU extension is unconstrained",
			tune: func(c *x509.Certificate) {
				c.DNSNames = []string{"edge.customer.example"}
			},
			want: true,
		},
		{
			name: "anyExtendedKeyUsage covers serverAuth",
			tune: func(c *x509.Certificate) {
				c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
				c.DNSNames = []string{"edge.customer.example"}
			},
			want: true,
		},
		{
			name: "client-only, which is what a platform node holds",
			tune: func(c *x509.Certificate) {
				c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			},
			want: false,
		},
		{
			// serverAuth but nothing to be a server FOR: no device could verify
			// the name it dialed, so this is not a usable listener certificate.
			name: "serverAuth with no name",
			tune: func(c *x509.Certificate) {
				c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			leaf := leafTuned(t, CommonName(42, "cn-chengdu"), tc.tune)
			id, err := FromLeaf(leaf)
			if err != nil {
				t.Fatalf("FromLeaf: %v", err)
			}
			if id.ServesInbound != tc.want {
				t.Errorf("ServesInbound = %v, want %v", id.ServesInbound, tc.want)
			}
		})
	}
}

func leafTuned(t *testing.T, cn string, tune func(*x509.Certificate)) *x509.Certificate {
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
	}
	tune(tmpl)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}
