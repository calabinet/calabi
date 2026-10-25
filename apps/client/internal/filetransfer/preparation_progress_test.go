package filetransfer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"
)

type slowHashReader struct {
	*bytes.Reader
	waited bool
}

func (r *slowHashReader) Read(b []byte) (int, error) {
	if !r.waited {
		time.Sleep(210 * time.Millisecond)
		r.waited = true
	}
	return r.Reader.Read(b[:min(len(b), 4096)])
}

func TestBatchPreparationReportsHashingAndConnectionOnResume(t *testing.T) {
	ip := netip.MustParseAddr("127.0.0.1")
	a, _ := NewIdentity()
	b, _ := NewIdentity()
	pacer, _ := NewPacer(512)
	s, err := NewBatchSender(a, ip, Peer{IP: ip, Fingerprint: b.Fingerprint}, 1, pacer, func() bool { return true }, "progress")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	data := bytes.Repeat([]byte("x"), 128<<10)
	var ticket BatchTicket
	for attempt := 0; attempt < 2; attempt++ {
		ctx, cancel := context.WithCancel(context.Background())
		var reports []PreparationProgress
		checkpoints := 0
		err := s.SendBatch(ctx, []Source{
			{Reader: &slowHashReader{Reader: bytes.NewReader(data)}, Name: "large.bin", Size: int64(len(data))},
			{Reader: bytes.NewReader(nil), Name: "empty.bin"},
		}, &ticket, func(BatchTicket) error { checkpoints++; return nil }, func(p BatchProgress) {
			if p.Preparation == nil {
				t.Fatal("network transfer reported before connection")
			}
			reports = append(reports, *p.Preparation)
			if p.Preparation.Phase == "connecting" {
				cancel()
			}
		})
		cancel()
		if !errors.Is(err, context.Canceled) || checkpoints != 1 {
			t.Fatalf("attempt %d: %v, checkpoints %d", attempt, err, checkpoints)
		}
		intermediate, empty, complete := false, false, false
		var previous int64
		for _, p := range reports {
			if p.Phase == "connecting" {
				if !complete || !empty {
					t.Fatal("connected before all source hashes completed")
				}
				continue
			}
			if p.Count != 2 || p.Bytes < 0 || p.Bytes > p.Size {
				t.Fatalf("invalid progress: %+v", p)
			}
			if p.Index == 0 {
				if p.Bytes < previous {
					t.Fatal("hash progress regressed")
				}
				previous = p.Bytes
				intermediate = intermediate || (p.Bytes > 0 && p.Bytes < p.Size)
				complete = complete || p.Bytes == int64(len(data))
			} else {
				empty = p.Name == "empty.bin" && p.Size == 0 && p.Bytes == 0
			}
		}
		if !intermediate || !complete || !empty {
			t.Fatalf("missing progress stages: %+v", reports)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var cancelledDuringHash bool
	err = s.SendBatch(ctx, []Source{
		{Reader: &slowHashReader{Reader: bytes.NewReader(data)}, Name: "large.bin", Size: int64(len(data))},
		{Reader: bytes.NewReader(nil), Name: "empty.bin"},
	}, &ticket, func(BatchTicket) error { t.Fatal("cancelled hash reached checkpoint"); return nil }, func(p BatchProgress) {
		if p.Preparation != nil && p.Preparation.Phase == "hashing" && p.Preparation.Bytes > 0 && p.Preparation.Bytes < p.Preparation.Size {
			cancelledDuringHash = true
			cancel()
		}
	})
	if !cancelledDuringHash || !errors.Is(err, context.Canceled) {
		t.Fatalf("hash could not be paused: %v", err)
	}
}

func TestPreparationKeepsConfirmedTransferAndDoesNotCountHashAsUpload(t *testing.T) {
	confirmed := BatchProgress{Batch: "batch", Index: 1, Count: 2, Transfer: Transfer{ID: "transfer", Name: "second.bin", Size: 1000, Offset: 400, State: "receiving"}}
	j := outgoingJob{record: outgoingRecord{Job: Job{Progress: confirmed, RateBps: 999, RemainingSeconds: 5}}}
	for _, phase := range []string{"hashing", "connecting"} {
		j.report(BatchProgress{Batch: "batch", Count: 2, Preparation: &PreparationProgress{Phase: phase, Index: 0, Name: "first.bin", Size: 10, Bytes: 5}})
		if j.record.Job.Progress.Transfer != confirmed.Transfer || j.record.Job.Progress.Index != 1 || j.record.Job.RateBps != 0 || j.record.Job.RemainingSeconds != 0 {
			t.Fatalf("preparation altered upload progress: %+v", j.record.Job)
		}
	}
	j.report(confirmed)
	if j.record.Job.Progress.Preparation != nil || j.record.Job.RateBps != 0 {
		t.Fatal("preparation leaked into resumed upload")
	}
}

var _ io.ReadSeeker = (*slowHashReader)(nil)
