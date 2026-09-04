package mesh

import "testing"

func TestDiscoKeyPublic(t *testing.T) {
	k, err := GenerateDiscoKey()
	if err != nil {
		t.Fatal(err)
	}
	if k.IsZero() {
		t.Fatal("generated disco key is zero")
	}
	pub := k.Public()
	if pub.IsZero() {
		t.Fatal("derived public disco key is zero")
	}
	if k.Public() != pub {
		t.Fatal("Public() is not deterministic for the same private key")
	}

	k2, err := GenerateDiscoKey()
	if err != nil {
		t.Fatal(err)
	}
	if k2.Public() == pub {
		t.Fatal("two independently generated keys share a public key")
	}
}
