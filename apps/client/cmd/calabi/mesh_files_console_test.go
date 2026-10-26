package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestNativeSaveReplacesOnlyAfterVerification(t *testing.T) {
	for _, failure := range []string{"", "partial write", "saved file checksum mismatch"} {
		t.Run(failure, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "received.bin")
			if err := os.WriteFile(target, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			err := writeVerifiedDestination(target, true, func(dst io.Writer) error {
				before, err := os.ReadFile(target)
				if err != nil || string(before) != "original" {
					t.Fatalf("destination changed before verification: %q %v", before, err)
				}
				if _, err := io.WriteString(dst, "verified content"); err != nil {
					return err
				}
				if failure != "" {
					return errors.New(failure)
				}
				return nil
			})
			if (err != nil) != (failure != "") {
				t.Fatalf("save error: %v", err)
			}
			want := "verified content"
			if failure != "" {
				want = "original"
			}
			body, err := os.ReadFile(target)
			if err != nil || string(body) != want {
				t.Fatalf("destination=%q, want %q: %v", body, want, err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 {
				t.Fatalf("temporary file leaked: %v %v", entries, err)
			}
		})
	}
}

func TestSaveNewFileAndExclusiveExport(t *testing.T) {
	for _, replace := range []bool{false, true} {
		dir := t.TempDir()
		target := filepath.Join(dir, "new.bin")
		copy := func(dst io.Writer) error { _, err := io.WriteString(dst, "body"); return err }
		if err := writeVerifiedDestination(target, replace, copy); err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile(target)
		if err != nil || string(body) != "body" {
			t.Fatalf("first save: %q %v", body, err)
		}
		called := false
		err = writeVerifiedDestination(target, false, func(io.Writer) error { called = true; return nil })
		if !errors.Is(err, os.ErrExist) || called {
			t.Fatalf("exclusive export overwrote file: %v called=%v", err, called)
		}
	}
}

func TestFailedNativeReplacementPreservesDirectory(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "folder")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	err := writeVerifiedDestination(target, true, func(dst io.Writer) error { _, err := io.WriteString(dst, "body"); return err })
	if err == nil {
		t.Fatal("replaced directory with a file")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || !entries[0].IsDir() {
		t.Fatalf("failed replacement changed directory or leaked temporary file: %v %v", entries, err)
	}
}
