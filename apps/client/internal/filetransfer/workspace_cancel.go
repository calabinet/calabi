package filetransfer

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"time"
)

// Bound the durable retry queue independently of the 32 visible task slots.
const maxOutgoingRecords = 512

// Caller holds w.mu or is opening the workspace.
func (w *Workspace) visibleJobs() int {
	count := 0
	for _, j := range w.jobs {
		if !j.record.Hidden {
			count++
		}
	}
	return count
}

// Caller holds w.mu, or has not yet exposed the newly opened workspace.
// Cancellation intent stays durable until the peer acknowledges it. Stopping
// this workspace leaves that intent for the next ordinary-user file agent.
func (w *Workspace) startWithdrawal(j *outgoingJob) {
	if w.closed || j.withdrawing {
		return
	}
	j.withdrawing = true
	ticket := j.record.Ticket
	ticket.Files = append([]FileTicket(nil), ticket.Files...)
	peerIP := j.record.Job.PeerIP
	w.withdrawals.Add(1)
	go func() {
		defer w.withdrawals.Done()
		defer func() { w.mu.Lock(); j.withdrawing = false; w.mu.Unlock() }()
		delay := time.Second
		for w.ctx.Err() == nil {
			ip, err := netip.ParseAddr(peerIP)
			if err == nil {
				var sender *BatchSender
				sender, err = w.Agent.Sender(ip)
				if err == nil {
					ctx, cancel := context.WithTimeout(w.ctx, 10*time.Second)
					err = sender.cancelBatch(ctx, &ticket, func(updated BatchTicket) error {
						w.mu.Lock()
						defer w.mu.Unlock()
						record := j.record
						record.Ticket = updated
						record.Ticket.Files = append([]FileTicket(nil), updated.Files...)
						if err := writeRecord(w.root, "job-"+j.record.Job.ID+".json", record); err != nil {
							return err
						}
						j.record.Ticket = record.Ticket
						return nil
					})
					cancel()
					sender.Close()
				}
			}
			if w.ctx.Err() != nil {
				return
			}
			w.mu.Lock()
			j.record.Job.CancelPending = err != nil
			j.record.Withdrawn = err == nil
			if err != nil {
				j.record.Job.Error = "cancelled locally; awaiting peer cancellation: " + err.Error()
			} else {
				j.record.Job.Error = ""
			}
			persistErr := writeRecord(w.root, "job-"+j.record.Job.ID+".json", j.record)
			if persistErr != nil {
				j.record.Withdrawn = false
				j.record.Job.CancelPending = true
				j.record.Job.Error = "cannot persist cancellation acknowledgment: " + persistErr.Error()
			}
			done := !j.record.Job.CancelPending
			if done && j.record.Hidden {
				if err := w.root.Remove("job-" + j.record.Job.ID + ".json"); err == nil || errors.Is(err, os.ErrNotExist) {
					delete(w.jobs, j.record.Job.ID)
				} else {
					done = false // Retry cleanup; never resurrect removed history.
				}
			}
			w.mu.Unlock()
			if done {
				return
			}
			if wait(w.ctx, delay) != nil {
				return
			}
			delay = min(30*time.Second, delay*2)
		}
	}()
}

// HasPendingCancellation includes hidden journals: removing history does not
// discard the network work required to withdraw an already offered file.
func (w *Workspace) HasPendingCancellation() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return false
	}
	for _, j := range w.jobs {
		if j.record.Job.State == "cancelled" && j.record.Job.CancelPending {
			return true
		}
	}
	return false
}

// NeedsControlSession keeps authenticated outgoing status and cancellation
// checks alive while reception is off. It never enables the incoming listener.
func (w *Workspace) NeedsControlSession() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return false
	}
	for _, j := range w.jobs {
		if j.record.Job.State == "sending" || j.record.Job.State == "cancelled" && j.record.Job.CancelPending {
			return true
		}
		if j.record.Job.State == "paused" {
			for _, file := range j.record.Ticket.Files {
				if validID(file.ID) && validID(file.Token) {
					return true
				}
			}
		}
	}
	return false
}
