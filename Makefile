.PHONY: build verify verify-build
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
# Rebuild the official binaries from THIS tree and check they are byte-for-byte
# what was released. Needs the manifest published beside the downloads:
#   curl -fsSLO https://download.calabi.net/latest/build-manifest.json
#   make verify-build MANIFEST=build-manifest.json
verify-build:
	bash scripts/verify-reproducible-build.sh $(MANIFEST) --tree .
