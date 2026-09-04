package main

import (
	"io"
	"log/slog"
	"reflect"
	"testing"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestParseServiceSpecs(t *testing.T) {
	got := parseServiceSpecs(quietLogger(), "db:tcp:5432, web:443 ,dns:udp:53")
	want := []meshServiceDecl{
		{Name: "db", Proto: "tcp", Port: 5432},
		{Name: "web", Proto: "tcp", Port: 443}, // proto defaults to tcp
		{Name: "dns", Proto: "udp", Port: 53},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// A malformed entry costs that entry, not the daemon: one bad line in a service
// unit must never keep the machine off the mesh.
func TestParseServiceSpecsSkipsBadEntries(t *testing.T) {
	got := parseServiceSpecs(quietLogger(), "nogood,db:tcp:5432,too:many:parts:here,x:0,y:99999,:443,web:80")
	want := []meshServiceDecl{
		{Name: "db", Proto: "tcp", Port: 5432},
		{Name: "web", Proto: "tcp", Port: 80},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseServiceSpecsEmpty(t *testing.T) {
	if got := parseServiceSpecs(quietLogger(), ""); got != nil {
		t.Fatalf("got %+v, want nil", got)
	}
}

// The YAML block and the flag must produce the same thing, including the tcp
// default — two entry points that disagree would be a nasty surprise.
func TestDeclaredServicesDefaultsProto(t *testing.T) {
	got := declaredServices([]meshServiceDecl{{Name: "web", Port: 443}, {Name: "dns", Proto: "udp", Port: 53}})
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].Proto != "tcp" {
		t.Errorf("empty proto = %q, want tcp", got[0].Proto)
	}
	if got[1].Proto != "udp" {
		t.Errorf("proto = %q, want udp", got[1].Proto)
	}
}
