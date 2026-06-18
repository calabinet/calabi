.PHONY: build verify
# .exe suffix on Windows (go build -o with an explicit name does NOT add it);
# empty on Linux/macOS.
EXE :=
ifeq ($(OS),Windows_NT)
EXE := .exe
endif
build:
	( cd apps/calabi-edge && go build -o ../../bin/calabi-edge$(EXE) ./cmd/calabi-edge )
	( cd apps/client      && go build -o ../../bin/calabi$(EXE)      ./cmd/calabi )
verify:
	bash scripts/verify-community.sh
