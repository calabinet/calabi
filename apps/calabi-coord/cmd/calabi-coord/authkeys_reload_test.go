package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeKeys(t *testing.T, path, body string, mtime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// Set the time explicitly: two writes inside one tick of the filesystem's
	// clock would otherwise look like no change at all.
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

// Adding and removing a key takes effect without a restart; an edit that does
// not parse keeps the keys already loaded.
func TestAuthKeysFileFollowsItsEdits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authkeys.json")
	base := time.Now().Add(-time.Hour)
	writeKeys(t, path, `{"old-key": {"meshnet": 1}}`, base)
	a, err := newFileAuth(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	admits := func(key string) bool { _, err := a.Resolve(ctx, key); return err == nil }
	if !admits("old-key") || admits("new-key") {
		t.Fatal("initial load is wrong")
	}
	if changed, _, _ := a.reload(); changed {
		t.Fatal("reload without an edit reported a change")
	}

	writeKeys(t, path, `{"new-key": {"meshnet": 1, "tags": ["tag:phone"]}}`, base.Add(time.Minute))
	if changed, n, err := a.reload(); !changed || err != nil || n != 1 {
		t.Fatalf("reload after an edit: changed=%v n=%d err=%v", changed, n, err)
	}
	if admits("old-key") || !admits("new-key") {
		t.Fatal("the edit did not take effect: old key still works or new key does not")
	}
	id, _ := a.Resolve(ctx, "new-key")
	if len(id.Tags) != 1 || id.Tags[0] != "tag:phone" {
		t.Fatalf("tags = %v", id.Tags)
	}

	writeKeys(t, path, `{"new-key": {"meshnet": 1},`, base.Add(2*time.Minute))
	if changed, _, err := a.reload(); !changed || err == nil {
		t.Fatalf("a broken edit: changed=%v err=%v; want a reported error", changed, err)
	}
	if !admits("new-key") {
		t.Fatal("a broken edit dropped the keys that were loaded")
	}
}

func TestAuthKeysFileRefusesKeysThatMeanSomethingElse(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"empty key":  `{"": {"meshnet": 1}}`,
		"meshnet 0":  `{"k": {"meshnet": 0}}`,
		"no meshnet": `{"k": {}}`,
		"negative":   `{"k": {"meshnet": -1}}`,
	} {
		path := filepath.Join(dir, "k.json")
		writeKeys(t, path, body, time.Now())
		if _, err := newFileAuth(path); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}
