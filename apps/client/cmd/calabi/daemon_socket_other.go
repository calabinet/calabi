//go:build !linux

package main

import (
	"errors"
	"net"
)

func listenDaemonSocket(string) (*net.UnixListener, error) {
	return nil, errors.New("the daemon management socket is supported on Linux")
}
