package listener

import "testing"

func TestACMEChallengeToken(t *testing.T) {
	cases := []struct {
		path      string
		wantTok   string
		wantMatch bool
	}{
		{"/.well-known/acme-challenge/abc123", "abc123", true},
		{"/.well-known/acme-challenge/abc123?x=1", "abc123", true},
		{"/.well-known/acme-challenge/", "", false},      // empty token
		{"/.well-known/acme-challenge/a/b", "", false},   // nested → reject
		{"/.well-known/acme-challenge", "", false},       // no trailing slash
		{"/index.html", "", false},                       // unrelated
		{"/foo/.well-known/acme-challenge/x", "", false}, // prefix not at start
	}
	for _, c := range cases {
		tok, ok := acmeChallengeToken(c.path)
		if ok != c.wantMatch || tok != c.wantTok {
			t.Errorf("acmeChallengeToken(%q) = (%q,%v); want (%q,%v)",
				c.path, tok, ok, c.wantTok, c.wantMatch)
		}
	}
}
