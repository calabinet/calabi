package main

import (
	"reflect"
	"testing"

	"github.com/calabinet/calabi/apps/client/internal/localweb"
	"github.com/calabinet/calabi/apps/client/internal/platform/statusapi"
)

// The two daemon kinds serve /v1/mesh from two different structs: the local
// daemon from localweb.MeshPeer, the platform daemon from statusapi.MeshPeer,
// bridged by toStatusapiMesh's hand-written field-by-field copy. Adding a field
// to one side compiles fine and silently drops the value on the other — which is
// exactly what happened to RTTMicros in 1.7.1: the mesh core measured it, the
// console never showed it, because everyone testing ran the local daemon while
// every installed Windows service is the platform one.
//
// These two tests pin both halves of that: the shapes agree, and the copy is
// total.

func TestMeshPeerShapesAgreeAcrossDaemonKinds(t *testing.T) {
	assertShapesAgree(t, reflect.TypeOf(localweb.MeshPeer{}), reflect.TypeOf(statusapi.MeshPeer{}))
}

// Same guard for the datapath counters. Go's struct conversion in
// toStatusapiMesh already forces the field names and types to match — it stops
// compiling otherwise — but conversion IGNORES struct tags, so the wire names
// can still drift apart silently. That is the half that matters: the SPA reads
// the json, not the Go.
func TestMeshDatapathShapesAgreeAcrossDaemonKinds(t *testing.T) {
	assertShapesAgree(t, reflect.TypeOf(localweb.MeshDatapath{}), reflect.TypeOf(statusapi.MeshDatapath{}))
}

// And the THIRD copy. `calabi mesh status` decodes /v1/mesh into its own
// anonymous struct in mesh.go, which the two guards above never touched — so a
// counter added to both daemons and forgotten here decodes as zero and PRINTS as
// zero. That is not a missing number, it is a wrong one, and it is precisely the
// failure that lost rtt_micros in 1.7.1.
//
// This one was found by a compile error rather than by a test, and only because
// the new field happened to be printed. A field added to the views and not
// printed would have slipped through in silence.
func TestMeshDatapathShapeMatchesTheCLIDecoder(t *testing.T) {
	cli, ok := reflect.TypeOf(meshStatusResp{}).FieldByName("Datapath")
	if !ok {
		t.Fatal("meshStatusResp has no Datapath field — rename it and this guard stops guarding")
	}
	view := reflect.TypeOf(statusapi.MeshDatapath{})
	byWire := map[string]reflect.StructField{}
	for i := 0; i < cli.Type.NumField(); i++ {
		f := cli.Type.Field(i)
		byWire[f.Tag.Get("json")] = f
	}
	for i := 0; i < view.NumField(); i++ {
		v := view.Field(i)
		name := v.Tag.Get("json")
		c, ok := byWire[name]
		if !ok {
			t.Errorf("the daemon reports %q (%s) and `calabi mesh status` does not decode it — "+
				"it will read as zero, which looks like an answer", name, v.Name)
			continue
		}
		if c.Type != v.Type {
			t.Errorf("%q: daemon has %s, the CLI decodes %s", name, v.Type, c.Type)
		}
	}
}

// The leg probe is a third shape crossing the same boundary, converted by a Go
// struct conversion in ProbeRelayLeg — so the field names and types cannot drift
// without a compile error, but the json TAGS can, silently, and the tags are what
// anyone reading the endpoint sees.
func TestMeshRelayProbeShapesAgreeAcrossDaemonKinds(t *testing.T) {
	assertShapesAgree(t, reflect.TypeOf(localweb.MeshRelayProbe{}), reflect.TypeOf(statusapi.MeshRelayProbe{}))
}

// nestedStructSlices reports whether both types are slices of structs — the one
// case where differing Go types are expected rather than a drift.
func nestedStructSlices(a, b reflect.Type) bool {
	return a.Kind() == reflect.Slice && b.Kind() == reflect.Slice &&
		a.Elem().Kind() == reflect.Struct && b.Elem().Kind() == reflect.Struct
}

func assertShapesAgree(t *testing.T, local, platform reflect.Type) {
	t.Helper()
	if local.NumField() != platform.NumField() {
		t.Fatalf("%s field count: localweb has %d, statusapi has %d",
			local.Name(), local.NumField(), platform.NumField())
	}
	for i := 0; i < local.NumField(); i++ {
		l, p := local.Field(i), platform.Field(i)
		switch {
		case l.Name != p.Name:
			t.Errorf("field %d: localweb %s, statusapi %s", i, l.Name, p.Name)
		case l.Type == p.Type:
			// identical type: nothing more to check
		case nestedStructSlices(l.Type, p.Type):
			// A slice of a NAMED struct cannot have the same Go type on both
			// sides — statusapi must not import localweb — so the types differ
			// by construction and comparing them by identity would reject every
			// correct implementation. Recurse instead: the element shapes are
			// what has to agree, and that is the thing the SPA actually reads.
			assertShapesAgree(t, l.Type.Elem(), p.Type.Elem())
		default:
			t.Errorf("field %s: localweb %s, statusapi %s", l.Name, l.Type, p.Type)
		}
		// The wire name matters more than the Go name: the same SPA reads both.
		if l.Tag.Get("json") != p.Tag.Get("json") {
			t.Errorf("field %s json tag: localweb %q, statusapi %q",
				l.Name, l.Tag.Get("json"), p.Tag.Get("json"))
		}
	}
}

func TestToStatusapiMeshCopiesEveryPeerField(t *testing.T) {
	// Every field non-zero, so a field the copy forgot lands as a zero we can spot
	// without naming the fields here — a new field is covered the day it is added.
	var src localweb.MeshPeer
	v := reflect.ValueOf(&src).Elem()
	for i := 0; i < v.NumField(); i++ {
		switch f := v.Field(i); f.Kind() {
		case reflect.String:
			f.SetString("x")
		case reflect.Int64:
			f.SetInt(7)
		case reflect.Bool:
			f.SetBool(true)
		case reflect.Slice:
			f.Set(reflect.MakeSlice(f.Type(), 1, 1))
		default:
			t.Fatalf("field %s: unhandled kind %s — teach this test to fill it",
				v.Type().Field(i).Name, f.Kind())
		}
	}

	got := toStatusapiMesh(localweb.MeshStatus{Peers: []localweb.MeshPeer{src}})
	if len(got.Peers) != 1 {
		t.Fatalf("peers: got %d, want 1", len(got.Peers))
	}
	out := reflect.ValueOf(got.Peers[0])
	for i := 0; i < out.NumField(); i++ {
		if out.Field(i).IsZero() {
			t.Errorf("field %s came out zero — toStatusapiMesh does not copy it",
				out.Type().Field(i).Name)
		}
	}
}

// MeshStatus is the same trap one level up, and the two shapes are NOT equal
// here — statusapi carries fields the local daemon has no concept of (a local
// pause, an org id). So the check is directional: everything the local daemon
// reports must have a counterpart, under the same wire name, on the platform
// one. The SPA is a single build serving both; a field that exists on only one
// side renders on only one kind of machine, which is how rtt_micros managed to
// be invisible on every installed Windows service while working in dev.
func TestMeshStatusFieldsSurviveTheCrossing(t *testing.T) {
	platform := map[string]reflect.StructField{}
	pt := reflect.TypeOf(statusapi.MeshStatus{})
	for i := 0; i < pt.NumField(); i++ {
		platform[pt.Field(i).Name] = pt.Field(i)
	}
	lt := reflect.TypeOf(localweb.MeshStatus{})
	for i := 0; i < lt.NumField(); i++ {
		l := lt.Field(i)
		p, ok := platform[l.Name]
		if !ok {
			t.Errorf("localweb.MeshStatus.%s has no counterpart in statusapi.MeshStatus", l.Name)
			continue
		}
		if l.Tag.Get("json") != p.Tag.Get("json") {
			t.Errorf("field %s json tag: localweb %q, statusapi %q",
				l.Name, l.Tag.Get("json"), p.Tag.Get("json"))
		}
	}
}

// And the crossing actually copies them. A subnet alias that does not reach the
// console is an address nobody can dial, which makes the whole scheme unusable
// on exactly the daemon kind every installed machine runs.
func TestToStatusapiMeshCarriesSubnetAliases(t *testing.T) {
	got := toStatusapiMesh(localweb.MeshStatus{
		SubnetAliases: []localweb.MeshSubnetAlias{{Alias: "100.96.5.0/24", Real: "192.168.1.0/24"}},
	})
	if len(got.SubnetAliases) != 1 {
		t.Fatalf("subnet aliases: %v, want one", got.SubnetAliases)
	}
	if got.SubnetAliases[0].Alias != "100.96.5.0/24" || got.SubnetAliases[0].Real != "192.168.1.0/24" {
		t.Errorf("mapping came across as %+v", got.SubnetAliases[0])
	}
}

// And the counters survive the crossing. Without this, the whole point of them
// is lost on exactly the daemon kind every installed machine runs: a datapath
// that reports zero drops because the copy forgot the field is worse than one
// that reports nothing, because it looks like an answer.
func TestToStatusapiMeshCopiesEveryDatapathField(t *testing.T) {
	var src localweb.MeshDatapath
	v := reflect.ValueOf(&src).Elem()
	for i := 0; i < v.NumField(); i++ {
		switch f := v.Field(i); f.Kind() {
		case reflect.Uint64:
			f.SetUint(7)
		case reflect.Int:
			f.SetInt(7)
		default:
			t.Fatalf("field %s: unhandled kind %s — teach this test to fill it",
				v.Type().Field(i).Name, f.Kind())
		}
	}
	out := reflect.ValueOf(toStatusapiMesh(localweb.MeshStatus{Datapath: src}).Datapath)
	for i := 0; i < out.NumField(); i++ {
		if out.Field(i).IsZero() {
			t.Errorf("field %s came out zero — toStatusapiMesh does not copy it",
				out.Type().Field(i).Name)
		}
	}
}
