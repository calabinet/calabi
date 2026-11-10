package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestBackgroundFileAgentReusesListenerAcrossDesktopExit(t *testing.T) {
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	var session uint32
	if err := windows.ProcessIdToSessionId(uint32(os.Getpid()), &session); err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf(`\\.\pipe\Calabi.DesktopFiles.test.%d.%d`, os.Getpid(), time.Now().UnixNano())
	listener, err := listenBackgroundFileAgent(path, account.Uid)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if duplicate, err := listenBackgroundFileAgent(path, account.Uid); err == nil {
		duplicate.Close()
		t.Fatal("two file agents claimed the same profile")
	} else if !backgroundFileAgentAlreadyListening(err) {
		t.Fatalf("duplicate start would fail the login task: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stopped := make(chan error, 1)
	go func() {
		stopped <- serveBackgroundFileAgentRPC(ctx, listener, session,
			func(action fileAction) (any, error) { return "desktop " + action.Action, nil },
			func(action fileAction) (any, error) { return "console " + action.Action, nil })
	}()
	if conn, err := dialBackgroundFileAgent(ctx, path, account.Uid, session+1); err == nil {
		conn.Close()
		t.Fatal("accepted a broker in another session")
	}
	exchange := func(client byte, action, want string) {
		t.Helper()
		conn, err := dialBackgroundFileAgent(ctx, path, account.Uid, session)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		deadline, _ := ctx.Deadline()
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write([]byte{client}); err != nil {
			t.Fatal(err)
		}
		if err := json.NewEncoder(conn).Encode(fileAction{Action: action}); err != nil {
			t.Fatal(err)
		}
		var got string
		if err := json.NewDecoder(conn).Decode(&got); err != nil || got != want {
			t.Fatalf("file action: got %q (%v), want %q", got, err, want)
		}
	}
	exchange(fileAgentDesktopClient, "snapshot", "desktop snapshot")
	exchange(fileAgentDesktopClient, "rdp_history", "desktop rdp_history")
	exchange(fileAgentConsoleClient, "console_stage", "console console_stage")
	exchange(fileAgentDesktopClient, "console_stage", "desktop console_stage")
	cancel()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("broker did not close after session cancellation")
	}
}
