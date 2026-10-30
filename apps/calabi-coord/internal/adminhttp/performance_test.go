package adminhttp_test

import (
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/adminhttp"
	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
)

func TestPerformanceSurfaceIsAggregateAndReadOnly(t *testing.T) {
	c := &core.Coordinator{Nodes: core.NewMemNodeStore(), Logger: slog.Default()}
	c.Performance.SentBytes.Add(1234)
	h := adminhttp.New(c, nil, c.Logger)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/admin/performance", nil))
	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
	var got core.PerformanceSnapshot
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.SentProtobufBytes != 1234 || got.Streams != 0 {
		t.Fatalf("wrong counters %+v", got)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/admin/performance", nil))
	if w.Code != 405 {
		t.Fatal("performance endpoint unexpectedly writable")
	}
}
