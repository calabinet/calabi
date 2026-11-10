//go:build windows && assistintegration

package mesh

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
)

// Try the wire APIs directly so a disabled menu cannot conceal a missing receiver check.
func checkIndependentReceivers(t *testing.T, agent *filetransfer.Agent, client *http.Client, base string) {
	t.Helper()
	request := func(method, path, body, token string, want int) []byte {
		t.Helper()
		req, err := http.NewRequest(method, base+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("X-File-Offset", "0")
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != want {
			t.Fatalf("%s %s status %d want %d: %v", method, path, resp.StatusCode, want, err)
		}
		return b
	}
	content := "independent receivers"
	offer, _ := json.Marshal(filetransfer.Offer{Name: "split.txt", BatchCount: 1, ClientID: strings.Repeat("1", 64), Batch: strings.Repeat("2", 64), Size: int64(len(content)), SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(content)))})
	request("POST", "/file/v1/offers", string(offer), "", 403)
	if err := agent.SetReceiving(true); err != nil {
		t.Fatal(err)
	}
	if err := agent.SetAssistance(false); err != nil {
		t.Fatal(err)
	}
	request("POST", "/assist/v1/session", `{"op":"request"}`, "", 403)
	var ticket struct{ ID, Token string }
	if err := json.Unmarshal(request("POST", "/file/v1/offers", string(offer), "", 201), &ticket); err != nil {
		t.Fatal(err)
	}
	if err := agent.Decide([]string{ticket.ID}, true); err != nil {
		t.Fatal(err)
	}
	path := "/file/v1/transfers/" + ticket.ID
	request("PUT", path, content, ticket.Token, 200)
	var receipt filetransfer.Transfer
	if err := json.NewDecoder(bytes.NewReader(request("POST", path+"/commit", "", ticket.Token, 200))).Decode(&receipt); err != nil || receipt.State != "completed" || receipt.Offset != int64(len(content)) {
		t.Fatal("file not completed", err)
	}
	if err := agent.SetAssistance(true); err != nil {
		t.Fatal(err)
	}
	if err := agent.SetReceiving(false); err != nil {
		t.Fatal(err)
	}
	request("GET", path, "", ticket.Token, 403)
	t.Log("file-only: file committed, direct assist request forbidden; assist-only: new file offer and previous file token forbidden")
}
