package filetransfer

import (
	"context"
	"net/netip"
	"time"
)

// A locally paused sender still learns if its current file was cancelled by
// the recipient. Read only known tickets; never recreate an offer while idle.
func (w *Workspace) watchPausedJobs() {
	w.withdrawals.Add(1)
	go func() {
		defer w.withdrawals.Done()
		for wait(w.ctx, 3*time.Second) == nil {
			w.mu.Lock()
			var jobs []outgoingRecord
			for _, j := range w.jobs {
				if j.cancel == nil && j.record.Job.State == "paused" && len(j.record.Ticket.Files) > 0 {
					record := j.record
					record.Ticket.Files = append([]FileTicket(nil), record.Ticket.Files...)
					jobs = append(jobs, record)
				}
			}
			w.mu.Unlock()
			for _, record := range jobs {
				index := record.Job.Progress.Index
				if index < 0 || index >= len(record.Ticket.Files) {
					continue
				}
				file := record.Ticket.Files[index]
				if !validID(file.ID) || !validID(file.Token) {
					continue
				}
				ip, err := netip.ParseAddr(record.Job.PeerIP)
				if err != nil {
					continue
				}
				sender, err := w.Agent.Sender(ip)
				if err != nil {
					continue
				}
				ctx, cancel := context.WithTimeout(w.ctx, 3*time.Second)
				var current Transfer
				err = sender.request(ctx, sender.control, "GET", "/transfers/"+file.ID, file.Token, nil, 0, 0, &current)
				cancel()
				sender.Close()
				if err != nil || validateTransfer(current, file) != nil || current.State != "cancelled" && current.State != "failed" {
					continue
				}
				w.mu.Lock()
				j := w.jobs[record.Job.ID]
				if !w.closed && j != nil && j.cancel == nil && j.record.Job.State == "paused" && j.record.Ticket.ID == record.Ticket.ID {
					previous := j.record.Job
					j.record.Job.State, j.record.Job.Error = "cancelled", ""
					j.record.Job.StopReason = current.StopReason
					if j.record.Job.StopReason == "" {
						j.record.Job.StopReason = "receiver_cancelled"
					}
					if current.State == "failed" {
						j.record.Job.StopReason = "receiver_failed"
					}
					j.record.Job.Progress.Transfer = current
					j.record.Job.CancelPending = true
					if err := writeRecord(w.root, "job-"+j.record.Job.ID+".json", j.record); err == nil {
						w.startWithdrawal(j)
					} else {
						j.record.Job = previous
						j.record.Job.Error = "cannot persist peer state: " + err.Error()
					}
				}
				w.mu.Unlock()
			}
		}
	}()
}
