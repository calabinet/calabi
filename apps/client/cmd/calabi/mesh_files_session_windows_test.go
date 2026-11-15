package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fileAgentSessionFixture(t *testing.T) (string, string) {
	t.Helper()
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("calabi-session-test-%d-%s", os.Getpid(), t.Name()), account.Uid
}

func fileAgentSessionChildEnv(t *testing.T, mode, path, sid string) []string {
	t.Helper()
	// A deliberately killed child cannot run TestMain's deferred home cleanup.
	// Keep its entire temporary home under the parent's cleanup directory.
	temporary := t.TempDir()
	return append(os.Environ(), "CALABI_SESSION_TEST_MODE="+mode, "CALABI_SESSION_TEST_PATH="+path,
		"CALABI_SESSION_TEST_SID="+sid, "TEMP="+temporary, "TMP="+temporary)
}

func TestFileAgentSessionDisconnectedDuplicatesExitAcrossProcesses(t *testing.T) {
	path, sid := fileAgentSessionFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waiting := make(chan struct{})
	var once sync.Once
	done := make(chan error, 1)
	go func() {
		done <- runFileAgentSession(ctx, path, sid, 42, time.Millisecond*10, func(uint32) bool {
			once.Do(func() { close(waiting) })
			return false
		}, func(context.Context) error { return errors.New("inactive session started serving") })
	}()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("waiting file agent did not exit after cancellation")
		}
	}()
	select {
	case <-waiting:
	case <-time.After(5 * time.Second):
		t.Fatal("first agent did not enter disconnected wait")
	}
	// Use separate OS processes: a process-local mutex or goroutine-only guard
	// would not protect desktop polls and the Windows logon task from each other.
	for i := 0; i < 8; i++ {
		childCtx, stop := context.WithTimeout(ctx, 5*time.Second)
		child := exec.CommandContext(childCtx, os.Args[0], "-test.run=^TestFileAgentSessionProcessHelper$", "-test.timeout=10s")
		child.Env = fileAgentSessionChildEnv(t, "duplicate", path, sid)
		output, err := child.CombinedOutput()
		stop()
		if err != nil {
			t.Fatalf("duplicate process %d did not exit cleanly: %v\n%s", i, err, output)
		}
	}
}

func TestFileAgentSessionClaimReleasedAfterProcessExit(t *testing.T) {
	path, sid := fileAgentSessionFixture(t)
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestFileAgentSessionProcessHelper$", "-test.timeout=15s")
	child.Env = fileAgentSessionChildEnv(t, "hold", path, sid)
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "claim-held\n" {
		t.Fatalf("claim readiness: %q %v", line, err)
	}
	if release, claimed, err := claimFileAgentSession(path, sid, 42); err != nil || claimed {
		if release != nil {
			release()
		}
		t.Fatalf("live process claim not exclusive: claimed=%v err=%v", claimed, err)
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	release, claimed, err := claimFileAgentSession(path, sid, 42)
	if err != nil || !claimed {
		t.Fatalf("dead process retained its claim: claimed=%v err=%v", claimed, err)
	}
	defer release()
}

func TestFileAgentSessionProcessHelper(t *testing.T) {
	mode := os.Getenv("CALABI_SESSION_TEST_MODE")
	if mode == "" {
		t.Skip("child process fixture")
	}
	path, sid := os.Getenv("CALABI_SESSION_TEST_PATH"), os.Getenv("CALABI_SESSION_TEST_SID")
	if mode == "hold" {
		release, claimed, err := claimFileAgentSession(path, sid, 42)
		if err != nil || !claimed {
			t.Fatalf("claim: %v %v", claimed, err)
		}
		defer release()
		fmt.Println("claim-held")
		time.Sleep(10 * time.Second)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	called := false
	err := runFileAgentSession(ctx, path, sid, 42, time.Millisecond*10, func(uint32) bool {
		called = true
		return false
	}, func(context.Context) error { return errors.New("duplicate started serving") })
	if err != nil || called {
		t.Fatalf("duplicate reached session wait: checked=%v err=%v", called, err)
	}
}

func TestFileAgentSessionDisconnectReconnectKeepsOneOwner(t *testing.T) {
	path, sid := fileAgentSessionFixture(t)
	var active atomic.Bool
	active.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan context.Context, 2)
	done := make(chan error, 1)
	go func() {
		done <- runFileAgentSession(ctx, path, sid, 42, time.Millisecond*10, func(uint32) bool { return active.Load() }, func(serving context.Context) error {
			started <- serving
			<-serving.Done()
			return nil
		})
	}()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("session lifecycle did not stop")
		}
	}()
	waitStarted := func() context.Context {
		t.Helper()
		select {
		case serving := <-started:
			return serving
		case <-time.After(5 * time.Second):
			t.Fatal("active session did not start serving")
			return nil
		}
	}
	first := waitStarted()
	active.Store(false)
	select {
	case <-first.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("disconnected session kept serving")
	}
	for i := 0; i < 100; i++ {
		if release, claimed, err := claimFileAgentSession(path, sid, 42); err != nil || claimed {
			if release != nil {
				release()
			}
			t.Fatalf("disconnected owner lost claim: %v %v", claimed, err)
		}
	}
	// Another Windows session may wait independently; the broker pipe still
	// prevents simultaneous serving with the same file identity.
	release, claimed, err := claimFileAgentSession(path, sid, 43)
	if err != nil || !claimed {
		t.Fatalf("claim crossed Windows sessions: %v %v", claimed, err)
	}
	release()
	active.Store(true)
	second := waitStarted()
	if second == first || second.Err() != nil {
		t.Fatal("reconnect reused the cancelled serving context")
	}
}
