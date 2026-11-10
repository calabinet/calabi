package main

import (
	"strings"
	"testing"
)

func TestPasteUILog(t *testing.T) {
	d := &desktopFileAgent{}
	l := &pasteUILog{agent: d}
	l.Write([]byte("ignored\npaste_ui visible=1 "))
	l.Write([]byte("topmost=1 show_ok=1 rect=1,2,3,4 error=0\n"))
	if len(d.handshakes) != 1 || d.handshakes[0].Action != "rdp_paste_ui" {
		t.Fatalf("missing log: %+v", d.handshakes)
	}
	l.Write([]byte(strings.Repeat("x", 1024)))
	if len(l.pending) != 0 {
		t.Fatal("unbounded partial log")
	}
	l.Write([]byte("paste_ui visible=1 topmost=0 show_ok=0 error=5\n"))
	if len(d.handshakes) != 2 || d.handshakes[1].Level != "WARN" {
		t.Fatal("window failure not reported")
	}
	l.Write([]byte("rdp_stream stage=seek hr=0x80030001 index=0 offset=0\n"))
	l.Write([]byte("rdp_stream stage=read hr=0x00000000 index=0 offset=0 requested=65536 received=16384\n"))
	if len(d.handshakes) != 4 || d.handshakes[2].Action != "rdp_paste_stream" || d.handshakes[2].Level != "WARN" || d.handshakes[3].Level != "INFO" {
		t.Fatalf("stream diagnostics missing: %+v", d.handshakes)
	}
}
