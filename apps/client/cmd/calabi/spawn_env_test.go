package main

import (
	"path/filepath"
	"testing"
)

func TestAbsolutizePathEnv(t *testing.T) {
	// An OS-appropriate absolute path (drive-rooted on Windows, /-rooted on Unix).
	absCA, err := filepath.Abs(filepath.Join("etc", "calabi", "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	in := []string{
		"PATH=/usr/bin",                              // untouched (not a target key)
		"CALABI_EDGE_CA_FILE=deploy/dev/certs/ca.crt", // relative → absolutized
		"CALABI_CONFIG=" + absCA,                      // already absolute → untouched
		"CALABI_SERVER=localhost:7443",                // not a target key → untouched
		"EMPTY=",                                      // empty value → untouched even if targeted
	}
	out := absolutizePathEnv(in, "CALABI_EDGE_CA_FILE", "CALABI_CONFIG", "EMPTY")

	got := map[string]string{}
	for _, kv := range out {
		if i := indexByte(kv, '='); i > 0 {
			got[kv[:i]] = kv[i+1:]
		}
	}

	if v := got["CALABI_EDGE_CA_FILE"]; !filepath.IsAbs(v) {
		t.Errorf("CALABI_EDGE_CA_FILE = %q, want absolute", v)
	}
	if got["CALABI_CONFIG"] != absCA {
		t.Errorf("CALABI_CONFIG = %q, want unchanged %q", got["CALABI_CONFIG"], absCA)
	}
	if got["PATH"] != "/usr/bin" || got["CALABI_SERVER"] != "localhost:7443" {
		t.Errorf("non-target vars were modified: PATH=%q CALABI_SERVER=%q", got["PATH"], got["CALABI_SERVER"])
	}
	if got["EMPTY"] != "" {
		t.Errorf("EMPTY = %q, want empty (unchanged)", got["EMPTY"])
	}
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
