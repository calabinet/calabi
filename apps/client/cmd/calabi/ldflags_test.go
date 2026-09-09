package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// `go build -ldflags "-X main.foo=bar"` only assigns to a package-level string
// VAR. Naming a const — or a symbol that does not exist — is SILENTLY IGNORED:
// the linker does not warn, the build succeeds, and the binary ships the value
// from the source. That is how edge/coord carried an unstamped version
// onwards, and how defaultServer shipped the dev address `localhost:7443` after
// being added to the release ldflags while sitting in the const block.
//
// So: every symbol the release script stamps must exist here as a var.
func TestLdflagsTargetsAreVars(t *testing.T) {
	script := filepath.Join("..", "..", "..", "..", "scripts", "package-release-client.sh")
	body, err := os.ReadFile(script)
	if err != nil {
		// Not every tree has the packaging scripts (the public export does not).
		// Skipping is right: this guards the script, and there is no script here.
		t.Skipf("release script not found (%v)", err)
	}

	stamped := regexp.MustCompile(`-X main\.([A-Za-z_][A-Za-z0-9_]*)=`).FindAllStringSubmatch(string(body), -1)
	if len(stamped) == 0 {
		t.Fatal("no `-X main.…` flags found in the release script — did it move? " +
			"this test then guards nothing")
	}

	vars, consts := packageLevelNames(t)
	for _, m := range stamped {
		name := m[1]
		switch {
		case vars[name]:
			// good
		case consts[name]:
			t.Errorf("release stamps -X main.%s but it is a CONST: the linker ignores that "+
				"silently and the release ships the source value. Make it a var.", name)
		default:
			t.Errorf("release stamps -X main.%s but no such package-level symbol exists: "+
				"the linker ignores that silently. Fix the name or drop the flag.", name)
		}
	}
}

// packageLevelNames splits this package's top-level declarations into var and
// const names. Only string-valued ones matter to -X, but recording both is what
// lets the failure above say WHICH mistake was made.
func packageLevelNames(t *testing.T) (vars, consts map[string]bool) {
	t.Helper()
	vars, consts = map[string]bool{}, map[string]bool{}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || filepath.Ext(n) != ".go" {
			continue
		}
		f, perr := parser.ParseFile(fset, n, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", n, perr)
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || (gd.Tok != token.VAR && gd.Tok != token.CONST) {
				continue
			}
			target := vars
			if gd.Tok == token.CONST {
				target = consts
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, id := range vs.Names {
					target[id.Name] = true
				}
			}
		}
	}
	return vars, consts
}
