package main

import (
	"os"

	"google.golang.org/grpc"

	"github.com/calabi/calabi/apps/client/internal/platform/meshenroll"
)

// dialCoord opens the gRPC connection to the mesh coordinator
// meshenroll.DialCoord). CALABI_INSECURE=1 dials plaintext instead — for dev /
// smoke stacks whose coord serves no TLS. It mirrors the edge control
// transport's CALABI_INSECURE escape hatch, so one flag makes a whole dev stack
// plaintext.
func dialCoord(addr string) (*grpc.ClientConn, error) {
	return meshenroll.DialCoord(addr, os.Getenv("CALABI_INSECURE") == "1")
}
