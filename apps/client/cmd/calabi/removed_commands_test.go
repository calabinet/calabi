// removed_commands_test.go — nothing may tell the user to run a command we deleted.
//
// `calabi ui` was removed and turned into a notice that exits 2. One line kept
// recommending it anyway: the LAST line of a successful `calabi login`, i.e.
// the most-read sentence the binary prints. It survived because deleting a
// command is a change in main.go's switch, while the strings that advertise it
// live anywhere — nothing connects the two, and nothing goes red.
//
// So connect them here. String literals only (via go/ast), never comments: a
// comment explaining why the command is gone is exactly what should be allowed
// to name it.
//
// RUN: go test./apps/client/cmd/calabi/ -run TestNoHintAdvertisesARemovedCommand -v
package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// removedCommands are the `calabi <x>` forms main.go answers with a refusal.
// Add to this list whenever a command is retired — that is the whole point:
// the removal and the ban on recommending it land in the same commit.
var removedCommands = []string{
	"calabi ui",       // removed: the daemon serves the dashboard; open the URL
	"calabi register", // removed: sign-up is web-console only
}

func TestNoHintAdvertisesARemovedCommand(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, name, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				return true
			}
			for _, cmd := range removedCommands {
				if !strings.Contains(s, cmd) {
					continue
				}
				// The refusal notice itself has to name the command — that is
				// the one string whose job is to say it is gone.
				if strings.Contains(strings.ToLower(s), "removed") {
					continue
				}
				t.Errorf("%s: a printed string recommends %q, which was removed and now "+
					"exits 2:\n    %q\nPoint the user at what replaced it. (If %q is back, "+
					"drop it from removedCommands in this file.)",
					fset.Position(lit.Pos()), cmd, s, cmd)
			}
			return true
		})
	}
}
