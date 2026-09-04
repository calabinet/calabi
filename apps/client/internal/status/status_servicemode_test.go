package status

import "testing"

// F2: /healthz exposes
// service_mode so the desktop shell can confirm it's attaching to the machine
// -wide system service. "system" iff the CALABI_SYSTEM_SERVICE marker is set.
func TestServiceMode(t *testing.T) {
	t.Setenv("CALABI_SYSTEM_SERVICE", "1")
	if got := serviceMode(); got != "system" {
		t.Errorf("with marker: serviceMode()=%q, want system", got)
	}
	t.Setenv("CALABI_SYSTEM_SERVICE", "")
	if got := serviceMode(); got != "user" {
		t.Errorf("without marker: serviceMode()=%q, want user", got)
	}
	t.Setenv("CALABI_SYSTEM_SERVICE", "0")
	if got := serviceMode(); got != "user" {
		t.Errorf("marker=0: serviceMode()=%q, want user", got)
	}
}
