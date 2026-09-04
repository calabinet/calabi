package adminhttp_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/calabi/calabi/apps/calabi-coord/internal/adminhttp"
	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
)

// The rename endpoint maps core's refusals onto the status codes the BFFs
// forward to users: a bad label or a taken name is a 400 with the reason (the
// old name stands), an unknown node is a 404, and a good rename returns the
// updated view with the name pinned.
func TestAdminRenameNode(t *testing.T) {
	c := newContractCoord()
	ctx := context.Background()
	a, _ := c.Register(ctx, core.RegisterInput{Meshnet: 1, Name: "daemon", NodeKey: ckey(1)})
	b, _ := c.Register(ctx, core.RegisterInput{Meshnet: 1, Name: "other", NodeKey: ckey(2)})
	h := adminhttp.New(c, core.NewNotifier(), slog.New(slog.NewTextHandler(os.Stderr, nil)))

	post := func(id int64, body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost,
			"/admin/nodes/"+itoa(id)+"/name", strings.NewReader(body))
		h.ServeHTTP(rr, r)
		return rr
	}

	rr := post(a.ID, `{"name":"Office-NAS"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("rename status = %d (body %s)", rr.Code, rr.Body.String())
	}
	var view map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if view["name"] != "office-nas" { // normalized
		t.Fatalf("name = %v, want office-nas", view["name"])
	}
	if view["name_pinned"] != true {
		t.Fatalf("name_pinned = %v, want true", view["name_pinned"])
	}
	if view["host_name"] != "daemon" {
		t.Fatalf("host_name = %v, want the node's self-reported daemon", view["host_name"])
	}

	if rr := post(b.ID, `{"name":"office-nas"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("taken name status = %d, want 400", rr.Code)
	}
	if rr := post(b.ID, `{"name":"not a label"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid name status = %d, want 400", rr.Code)
	}
	if rr := post(4242, `{"name":"ghost"}`); rr.Code != http.StatusNotFound {
		t.Fatalf("unknown node status = %d, want 404", rr.Code)
	}
	// The refused renames left the node alone.
	got, _ := c.Nodes.Get(ctx, b.ID)
	if got.Name != "other" {
		t.Fatalf("name after refused renames = %q, want other", got.Name)
	}
}

// The preview endpoint answers for a doc that would be REFUSED on save (zero
// rules): that is precisely when an admin needs the number, because it is the
// explanation for the refusal.
func TestAdminPreviewAndCheckACL(t *testing.T) {
	c := newContractCoord()
	c.ACL = core.NewMemACLStore()
	ctx := context.Background()
	_, _ = c.Register(ctx, core.RegisterInput{Meshnet: 1, Name: "a", NodeKey: ckey(1)})
	_, _ = c.Register(ctx, core.RegisterInput{Meshnet: 1, Name: "b", NodeKey: ckey(2)})
	h := adminhttp.New(c, core.NewNotifier(), slog.New(slog.NewTextHandler(os.Stderr, nil)))

	post := func(path, body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
		return rr
	}

	// Empty doc: valid to preview (invalid to save) and it reports the cut.
	rr := post("/admin/meshnets/1/acl/preview", `{"groups":{},"acls":[]}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("preview status = %d (body %s)", rr.Code, rr.Body.String())
	}
	var diff struct {
		TotalPairs int `json:"total_pairs"`
		Removed    []struct {
			AName string `json:"a_name"`
			BName string `json:"b_name"`
		} `json:"removed"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &diff); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if diff.TotalPairs != 1 || len(diff.Removed) != 1 {
		t.Fatalf("preview = %+v, want the single a↔b pair cut", diff)
	}

	// The checker reports the live default (allow-all) as reachable.
	rr = post("/admin/meshnets/1/acl/check", `{"src":"a","dst":"b"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("check status = %d (body %s)", rr.Code, rr.Body.String())
	}
	var chk struct {
		Reachable bool `json:"reachable"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &chk)
	if !chk.Reachable {
		t.Fatal("with no stored doc the meshnet is allow-all; check should say reachable")
	}

	// An unknown node name is a 404, not a silent "denied".
	if rr := post("/admin/meshnets/1/acl/check", `{"src":"a","dst":"ghost"}`); rr.Code != http.StatusNotFound {
		t.Fatalf("unknown node check = %d, want 404", rr.Code)
	}
}
