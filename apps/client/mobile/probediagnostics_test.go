package mobile

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/calabinet/calabi/apps/client/internal/localweb"
	"github.com/calabinet/calabi/apps/client/internal/mesh"
)

func TestMobileDatapathDiagnosticsMatchDesktopWireNames(t *testing.T) {
	a, b := reflect.TypeOf(mesh.DatapathStats{}), reflect.TypeOf(localweb.MeshDatapath{})
	if a.NumField() != b.NumField() {
		t.Fatal("datapath shape drift")
	}
	for i := 0; i < a.NumField(); i++ {
		x, y := a.Field(i), b.Field(i)
		if x.Name != y.Name || x.Type != y.Type || x.Tag.Get("json") != y.Tag.Get("json") {
			t.Fatalf("wire mismatch for %s", x.Name)
		}
	}
	st := meshStatus{Datapath: &mesh.DatapathStats{ProbeSent: 3, ProbeSchedulerRuns: 2}}
	data, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err = json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	var diagnostics map[string]any
	if err = json.Unmarshal(got["datapath"], &diagnostics); err != nil {
		t.Fatal(err)
	}
	if diagnostics["probe_sent"] != float64(3) || diagnostics["probe_scheduler_runs"] != float64(2) {
		t.Fatal("mobile diagnostics missing")
	}
}
