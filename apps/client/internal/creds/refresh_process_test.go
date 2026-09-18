package creds

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The helper process reads these; see TestRefreshSessionHelperProcess.
const (
	xprocFileEnv   = "CALABI_TEST_XPROC_CREDS"
	xprocURLEnv    = "CALABI_TEST_XPROC_EXCHANGE"
	xprocRoundsEnv = "CALABI_TEST_XPROC_ROUNDS"
)

// Two processes sharing one creds file must not spend the same refresh token.
//
// On a desktop that is the CLI beside a running daemon; on a phone it is the app
// beside its VPN extension, which iOS runs as separate processes by design. A
// refresh token is good for one exchange, so the process that loses the race
// comes back refused — and a refused refresh is a sign-out.
func TestRefreshSessionAcrossProcesses(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns helper processes")
	}
	// identity-svc, over HTTP so both processes spend against the same one. The
	// delay widens the window in which two exchanges could overlap.
	idp := &rotating{current: "usr_r0", delay: 5 * time.Millisecond}
	var replays atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rt, _ := io.ReadAll(r.Body)
		access, next, err := idp.exchange(r.Context(), string(rt))
		if err != nil {
			replays.Add(1)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode([2]string{access, next})
	}))
	defer srv.Close()

	file := filepath.Join(t.TempDir(), "creds.json")
	t.Setenv("CALABI_CONFIG", file)
	if err := Save(&Config{AccessToken: "jwt-0", RefreshToken: "usr_r0"}); err != nil {
		t.Fatal(err)
	}

	const rounds = 100
	var wg sync.WaitGroup
	outs := make([]string, 2)
	errs := make([]error, 2)
	for i := range outs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmd := exec.Command(os.Args[0], "-test.run=^TestRefreshSessionHelperProcess$", "-test.count=1", "-test.v")
			cmd.Env = append(os.Environ(),
				xprocFileEnv+"="+file, xprocURLEnv+"="+srv.URL, xprocRoundsEnv+"="+strconv.Itoa(rounds))
			out, err := cmd.CombinedOutput()
			outs[i], errs[i] = string(out), err
		}()
	}
	wg.Wait()

	for i := range outs {
		if errs[i] != nil || !strings.Contains(outs[i], "--- PASS: TestRefreshSessionHelperProcess") {
			t.Errorf("process %d: %v\n%s", i, errs[i], outs[i])
		}
	}
	if n := replays.Load(); n != 0 {
		t.Errorf("%d refresh tokens were spent twice: the processes raced each other's exchange", n)
	}
	idp.mu.Lock()
	exchanged := idp.n
	idp.mu.Unlock()
	if exchanged == 0 {
		t.Error("no exchange ever happened; the test proved nothing")
	}
	t.Logf("%d exchanges served %d refreshes across two processes", exchanged, 2*rounds)
}

// TestRefreshSessionHelperProcess is one of the two processes above. It refuses
// the token it last obtained, over and over: each round either spends the
// refresh token or picks up what the other process just saved. A round that
// comes back empty is the sign-out the lock exists to prevent.
func TestRefreshSessionHelperProcess(t *testing.T) {
	file := os.Getenv(xprocFileEnv)
	if file == "" {
		t.Skip("helper for TestRefreshSessionAcrossProcesses")
	}
	// testhome cleared CALABI_CONFIG for this process; point it back at the
	// shared file.
	t.Setenv("CALABI_CONFIG", file)
	rounds, _ := strconv.Atoi(os.Getenv(xprocRoundsEnv))
	url := os.Getenv(xprocURLEnv)
	exchange := func(ctx context.Context, rt string) (string, string, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(rt))
		if err != nil {
			return "", "", err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return "", "", fmt.Errorf("exchange: %s", resp.Status)
		}
		var pair [2]string
		if err := json.NewDecoder(resp.Body).Decode(&pair); err != nil {
			return "", "", err
		}
		return pair[0], pair[1], nil
	}

	last := "jwt-0"
	for i := 0; i < rounds; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		tok := RefreshSession(ctx, last, exchange)
		cancel()
		if tok == "" {
			t.Fatalf("round %d: refreshing %q came back empty (signed out)", i, last)
		}
		last = tok
	}
}
