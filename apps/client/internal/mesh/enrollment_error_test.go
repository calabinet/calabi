package mesh

import (
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestEnrollmentErrorOnlyClassifiesRegistrationQuota(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"none", nil, ""},
		{"quota", fmt.Errorf("%w: %w", ErrRegister, status.Error(codes.ResourceExhausted, "limit reached")), "device_limit"},
		{"stream exhaustion", status.Error(codes.ResourceExhausted, "stream budget"), ""},
		{"unavailable", fmt.Errorf("%w: %w", ErrRegister, status.Error(codes.Unavailable, "offline")), ""},
		{"disabled", fmt.Errorf("%w: %w", ErrRegister, status.Error(codes.PermissionDenied, "disabled")), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := EnrollmentError(tc.err); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
