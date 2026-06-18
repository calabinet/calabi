//go:build windows

package main

import (
	"net"
	"os"
	"testing"
)

// Real integration check on Windows: open a listener, then confirm pidOnPort
// parses `netstat -ano` and finds OUR process owning that port. Guards the
// netstat column layout / parsing the whole feature depends on.
func TestPidOnPort_FindsOurListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	pid, ok := pidOnPort(port)
	if !ok {
		t.Fatalf("pidOnPort(%d) found no listener", port)
	}
	if pid != os.Getpid() {
		t.Fatalf("pidOnPort(%d) = %d, want our pid %d", port, pid, os.Getpid())
	}
}

// A port nobody is listening on returns (0, false).
func TestPidOnPort_NoListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // free it

	if pid, ok := pidOnPort(port); ok {
		t.Fatalf("pidOnPort(%d) = %d, want none after close", port, pid)
	}
}
