package mesh

import (
	"testing"
	"time"
)

func TestReceiveSimulationDropsCompleteDatagramsAndClosesPromptly(t *testing.T) {
	b := testBind()
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	b.simulatedDropEvery.Store(3)
	for i := 1; i <= 9; i++ {
		b.enqueue(nil, []byte{byte(i)})
	}
	if len(b.recv) != 6 || b.rxDropped.Load() != 3 {
		t.Fatal("loss injection did not discard whole datagrams")
	}
	for _, expected := range []byte{1, 2, 4, 5, 7, 8} {
		if actual := (<-b.recv).pkt; len(actual) != 1 || actual[0] != expected {
			t.Fatal("packet bytes/order changed")
		}
	}
	b.simulatedDropEvery.Store(0)
	b.simulatedDelayMs.Store(100)
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { b.enqueue(nil, []byte{10}); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("simulated receive ignored bind close")
	}
	if len(b.recv) != 0 {
		t.Fatal("closed bind accepted delayed traffic")
	}
}
