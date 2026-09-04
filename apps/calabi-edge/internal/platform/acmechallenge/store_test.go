package acmechallenge

import (
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/calabi/calabi/pkg/certevents"
	eventbus "github.com/calabi/calabi/apps/calabi-edge/internal/bus"
)

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestStore_PresentResolveCleanup(t *testing.T) {
	s := &Store{tokens: map[string]entry{}, ttl: time.Hour, logger: slog.Default()}

	s.onPresent(&eventbus.Msg{Data: mustJSON(t, certevents.ChallengeEvent{
		Token: "tok1", KeyAuth: "tok1.thumb", Domain: "app.example.com",
	})})

	got, ok := s.Resolve("tok1")
	if !ok || got != "tok1.thumb" {
		t.Fatalf("Resolve after present = (%q,%v); want (tok1.thumb,true)", got, ok)
	}

	s.onCleanup(&eventbus.Msg{Data: mustJSON(t, certevents.ChallengeEvent{Token: "tok1"})})
	if _, ok := s.Resolve("tok1"); ok {
		t.Fatal("Resolve after cleanup: expected miss")
	}
}

func TestStore_Expiry(t *testing.T) {
	s := &Store{tokens: map[string]entry{}, ttl: 5 * time.Millisecond, logger: slog.Default()}
	s.onPresent(&eventbus.Msg{Data: mustJSON(t, certevents.ChallengeEvent{Token: "t", KeyAuth: "k"})})
	time.Sleep(10 * time.Millisecond)
	if _, ok := s.Resolve("t"); ok {
		t.Fatal("expected miss after TTL elapsed")
	}
}

func TestStore_BadPayloadIgnored(t *testing.T) {
	s := &Store{tokens: map[string]entry{}, ttl: time.Hour, logger: slog.Default()}
	s.onPresent(&eventbus.Msg{Data: []byte("not json")}) // must not panic
	if _, ok := s.Resolve("anything"); ok {
		t.Fatal("bad payload should install nothing")
	}
}
