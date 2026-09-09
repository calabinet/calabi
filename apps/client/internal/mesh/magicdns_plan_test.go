package mesh

import (
	"errors"
	"testing"
)

const magicIP = "100.100.100.100"

// Taking /etc/resolv.conf over wrong costs the HOST all DNS, not just the mesh.
// These are the states a machine can actually be in when the daemon starts.
func TestPlanResolvTakeover(t *testing.T) {
	host := []byte("nameserver 192.168.1.1\nsearch lan\n")
	ours := []byte("nameserver " + magicIP + "\nsearch mesh\n")

	t.Run("a normal machine", func(t *testing.T) {
		p, err := planResolvTakeover(host, nil, magicIP)
		if err != nil {
			t.Fatal(err)
		}
		if p.Upstream != "192.168.1.1:53" {
			t.Errorf("upstream %q, want the host's own resolver", p.Upstream)
		}
		if string(p.Restore) != string(host) || string(p.Backup) != string(host) {
			t.Errorf("must restore and back up the host's config, got restore=%q backup=%q", p.Restore, p.Backup)
		}
	})

	// The case that broke a machine: a previous run rewrote the file and never
	// restored it (killed / crashed / rebooted). Reading that file as "the
	// host's config" finds no upstream, and writing it back as the "original"
	// makes the damage permanent.
	t.Run("our own leftover, with a backup", func(t *testing.T) {
		p, err := planResolvTakeover(ours, host, magicIP)
		if err != nil {
			t.Fatal(err)
		}
		if p.Upstream != "192.168.1.1:53" {
			t.Errorf("upstream %q, want the one from the BACKUP", p.Upstream)
		}
		if string(p.Restore) != string(host) {
			t.Errorf("restore = %q, want the host's real config", p.Restore)
		}
		if p.Backup != nil {
			t.Errorf("backup = %q, want it left alone — overwriting it loses the original", p.Backup)
		}
	})

	// No backup either: we cannot name an upstream, so taking over would leave
	// the host with a resolver that can answer nothing. Refuse.
	t.Run("our own leftover, no backup", func(t *testing.T) {
		if _, err := planResolvTakeover(ours, nil, magicIP); !errors.Is(err, ErrNoUpstreamResolver) {
			t.Fatalf("err = %v, want ErrNoUpstreamResolver", err)
		}
	})

	t.Run("an empty resolv.conf", func(t *testing.T) {
		if _, err := planResolvTakeover(nil, nil, magicIP); !errors.Is(err, ErrNoUpstreamResolver) {
			t.Fatalf("err = %v, want ErrNoUpstreamResolver", err)
		}
	})

	t.Run("only comments and a search line", func(t *testing.T) {
		c := []byte("# generated\nsearch lan\noptions edns0\n")
		if _, err := planResolvTakeover(c, nil, magicIP); !errors.Is(err, ErrNoUpstreamResolver) {
			t.Fatalf("err = %v, want ErrNoUpstreamResolver", err)
		}
	})

	// A stale backup that is itself ours must not be trusted as an upstream.
	t.Run("both files are ours", func(t *testing.T) {
		if _, err := planResolvTakeover(ours, ours, magicIP); !errors.Is(err, ErrNoUpstreamResolver) {
			t.Fatalf("err = %v, want ErrNoUpstreamResolver", err)
		}
	})

	t.Run("several nameservers keeps the first", func(t *testing.T) {
		c := []byte("nameserver 1.1.1.1\nnameserver 8.8.8.8\n")
		p, err := planResolvTakeover(c, nil, magicIP)
		if err != nil {
			t.Fatal(err)
		}
		if p.Upstream != "1.1.1.1:53" {
			t.Errorf("upstream %q, want 1.1.1.1:53", p.Upstream)
		}
	})
}

func TestPointsAt(t *testing.T) {
	if !pointsAt("nameserver "+magicIP+"\n", magicIP) {
		t.Error("did not recognise our own config")
	}
	if pointsAt("nameserver 1.1.1.1\n", magicIP) {
		t.Error("mistook the host's config for ours")
	}
	if pointsAt("# nameserver "+magicIP+"\n", magicIP) {
		t.Error("a commented-out line is not a nameserver")
	}
}

func TestRenderResolvConf(t *testing.T) {
	if got := string(renderResolvConf(magicIP, "mesh")); got != "nameserver "+magicIP+"\nsearch mesh\n" {
		t.Errorf("render = %q", got)
	}
	if got := string(renderResolvConf(magicIP, "")); got != "nameserver "+magicIP+"\n" {
		t.Errorf("render without a suffix = %q", got)
	}
}
