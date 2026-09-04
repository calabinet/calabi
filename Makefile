.PHONY: build verify verify-build verify-build-here
# .exe suffix on Windows (go build -o with an explicit name does NOT add it);
# empty on Linux/macOS.
EXE :=
ifeq ($(OS),Windows_NT)
EXE := .exe
endif
build:
	( cd apps/calabi-edge && go build -o ../../bin/calabi-edge$(EXE) ./cmd/calabi-edge )
	( cd apps/client      && go build -o ../../bin/calabi$(EXE)      ./cmd/calabi )
	( cd apps/calabi-coord  && go build -o ../../bin/calabi-coord$(EXE)  ./cmd/calabi-coord )
verify:
	bash scripts/verify-public-tree.sh
# Rebuild the official binaries and check they are byte-for-byte what was
# released. Needs the manifest published beside the downloads:
#   curl -fsSLO https://download.calabi.net/latest/build-manifest.json
#   make verify-build MANIFEST=build-manifest.json
#
# This clones the repo at the commit the manifest names rather than using the
# tree you are standing in. That is the whole point: a fresh checkout is where
# line endings, VCS stamping and a stale working tree can bite, and skipping it
# is how three separate release bugs stayed invisible through a green check.
# verify-build-here is the debugging shortcut - faster, and it trusts your tree.
verify-build:
	bash scripts/verify-reproducible-build.sh $(MANIFEST)
verify-build-here:
	bash scripts/verify-reproducible-build.sh $(MANIFEST) --tree .
