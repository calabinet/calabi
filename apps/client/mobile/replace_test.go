package mobile

import (
	"fmt"
	"net/http"
	"runtime"
	"testing"
)

// The fleet the replace tests sign in to: user 42 in org 7.
func replaceFleet() string {
	os := runtime.GOOS
	other := "windows"
	if os == other {
		other = "linux"
	}
	return fmt.Sprintf(`{"is_manager": false, "items": [
		{"id": 1, "name": "pixel-8", "overlay": "100.64.0.1", "os": %[1]q, "owner_user_id": 42, "online": false, "last_seen": "2026-09-01T10:00:00+08:00"},
		{"id": 2, "name": "pixel-9", "overlay": "100.64.0.2", "os": %[1]q, "owner_user_id": 42, "online": false, "last_seen": "2026-09-15T10:00:00+08:00", "disabled": true},
		{"id": 3, "name": "in-my-pocket", "overlay": "100.64.0.3", "os": %[1]q, "owner_user_id": 42, "online": true},
		{"id": 4, "name": "teammates", "overlay": "100.64.0.4", "os": %[1]q, "owner_user_id": 43, "online": false},
		{"id": 5, "name": "laptop", "overlay": "100.64.0.5", "os": %[2]q, "owner_user_id": 42, "online": false},
		{"id": 6, "name": "kiosk", "overlay": "100.64.0.6", "os": %[1]q, "owner_user_id": 42, "online": false, "tags": ["tag:kiosk"]},
		{"id": 7, "name": "router", "overlay": "100.64.0.7", "os": %[1]q, "owner_user_id": 42, "online": false, "approved_routes": ["192.168.1.0/24"]},
		{"id": 8, "name": "this-phone", "overlay": "100.64.0.8", "os": %[1]q, "owner_user_id": 42, "online": false},
		{"id": 9, "name": "unowned", "overlay": "100.64.0.9", "os": %[1]q, "owner_user_id": 0, "online": false}
	]}`, os, other)
}

func TestReplaceableIsThisUsersOfflineDevicesOnThisPlatform(t *testing.T) {
	bff := &fakeBFF{nodes: replaceFleet()}
	c := newTestCore(t, bff, &fakePlatform{})
	signIn(t, c)
	c.rememberSelf(7, "100.64.0.8") // this phone, disconnected

	code, body := call(t, c, "GET", "/v1/mesh/replaceable", "")
	if code != http.StatusOK {
		t.Fatalf("replaceable = %d %v", code, body)
	}
	items, _ := body["items"].([]any)
	var got []float64
	for _, it := range items {
		got = append(got, it.(map[string]any)["id"].(float64))
	}
	// Newest first; not the online one, a teammate's, another platform's, a
	// tagged or routing device, this phone, or one nobody owns.
	if fmt.Sprint(got) != "[2 1]" {
		t.Fatalf("replaceable ids = %v, want [2 1]", got)
	}
}

func TestReplaceDeletesTheOldDeviceAndTakesItsName(t *testing.T) {
	bff := &fakeBFF{nodes: replaceFleet()}
	c := newTestCore(t, bff, &fakePlatform{})
	signIn(t, c)

	code, body := call(t, c, "POST", "/v1/mesh/replace", `{"node_id": 1}`)
	if code != http.StatusOK || body["device_name"] != "pixel-8" {
		t.Fatalf("replace = %d %v, want the settings with the old name", code, body)
	}
	if fmt.Sprint(bff.deleted) != "[/v1/mesh/nodes/1]" {
		t.Fatalf("deleted %v, want exactly the old device", bff.deleted)
	}
	if _, s := call(t, c, "GET", "/v1/settings", ""); s["device_name"] != "pixel-8" {
		t.Fatalf("settings after replace = %v", s)
	}
}

// The list the app showed may be stale: a device that is online now, or was
// never a candidate, is not deleted whatever id the app sends.
func TestReplaceRefusesADeviceThatIsNotACandidate(t *testing.T) {
	bff := &fakeBFF{nodes: replaceFleet()}
	c := newTestCore(t, bff, &fakePlatform{})
	signIn(t, c)
	_, before := call(t, c, "GET", "/v1/settings", "")

	for _, id := range []int{3, 4, 7, 404} {
		if code, body := call(t, c, "POST", "/v1/mesh/replace", fmt.Sprintf(`{"node_id": %d}`, id)); code != http.StatusConflict {
			t.Errorf("replace %d = %d %v, want 409", id, code, body)
		}
	}
	if len(bff.deleted) != 0 {
		t.Fatalf("deleted %v, want nothing", bff.deleted)
	}
	if _, after := call(t, c, "GET", "/v1/settings", ""); after["device_name"] != before["device_name"] {
		t.Fatalf("device name changed from %v to %v", before["device_name"], after["device_name"])
	}
}

// When the control plane will not delete the old device, this phone keeps its
// own name: two devices must not end up answering to one.
func TestReplaceKeepsTheNameWhenTheDeleteIsRefused(t *testing.T) {
	bff := &fakeBFF{nodes: replaceFleet(), deleteStatus: http.StatusForbidden}
	c := newTestCore(t, bff, &fakePlatform{})
	signIn(t, c)
	_, before := call(t, c, "GET", "/v1/settings", "")

	if code, _ := call(t, c, "POST", "/v1/mesh/replace", `{"node_id": 1}`); code != http.StatusForbidden {
		t.Fatalf("replace = %d, want the upstream 403", code)
	}
	if _, after := call(t, c, "GET", "/v1/settings", ""); after["device_name"] != before["device_name"] {
		t.Fatalf("device name changed to %v after a refused delete", after["device_name"])
	}
}
