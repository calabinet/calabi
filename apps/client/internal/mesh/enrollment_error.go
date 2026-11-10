package mesh

import (
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// EnrollmentError exposes a stable reason without leaking RPC diagnostics to UI.
// Resource exhaustion after registration (for example on a netmap stream) is
// deliberately not interpreted as a device seat refusal.
func EnrollmentError(err error) string {
	if errors.Is(err, ErrRegister) && status.Code(err) == codes.ResourceExhausted {
		return "device_limit"
	}
	return ""
}
