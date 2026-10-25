package filetransfer

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

type StagedFile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Size int64  `json:"size"`
}
type Job struct {
	StopReason       string        `json:"stop_reason,omitempty"`
	CancelPending    bool          `json:"cancel_pending,omitempty"`
	RateBps          int64         `json:"rate_bps,omitempty"`
	RemainingSeconds int64         `json:"remaining_seconds,omitempty"`
	ID               string        `json:"id"`
	PeerIP           string        `json:"peer_ip"`
	Sources          []string      `json:"sources"`
	State            string        `json:"state"`
	Error            string        `json:"error,omitempty"`
	Progress         BatchProgress `json:"progress"`
}
type outgoingRecord struct {
	Hidden    bool        `json:"hidden,omitempty"`
	Withdrawn bool        `json:"withdrawn,omitempty"`
	Job       Job         `json:"job"`
	Ticket    BatchTicket `json:"ticket"`
}
type outgoingJob struct {
	withdrawing bool
	lastTime    time.Time
	lastID      string
	lastOffset  int64
	record      outgoingRecord
	cancel      context.CancelFunc
	done        chan struct{}
}

func (j *outgoingJob) report(p BatchProgress) {
	if a := p.activity; a != nil {
		tr := j.record.Job.Progress.Transfer
		if j.record.Job.State == "sending" && tr.ID == a.id && (tr.State == "accepted" || tr.State == "receiving" || tr.State == "waiting_sender") && j.record.Job.Progress.Preparation == nil {
			j.record.Job.RateBps, j.record.Job.RemainingSeconds = a.rate, a.remaining
			j.lastTime = a.at
		}
		return
	}
	if p.Preparation != nil {
		// Hashing never changes bytes already confirmed by the receiver.
		p.Transfer = j.record.Job.Progress.Transfer
		p.Index = j.record.Job.Progress.Index
		j.record.Job.Progress = p
		j.record.Job.RateBps = 0
		j.record.Job.RemainingSeconds = 0
		return
	}
	now := time.Now()
	tr := p.Transfer
	if tr.ID != j.lastID || tr.Offset == 0 || tr.State == "paused" || tr.State == "waiting" || tr.State == "verifying" || tr.State == "committing" {
		j.lastID = tr.ID
		j.lastOffset = tr.Offset
		j.lastTime = now
		j.record.Job.RateBps = 0
		j.record.Job.RemainingSeconds = 0
	} else if tr.Offset > j.lastOffset {
		j.lastOffset = tr.Offset
	}
	j.record.Job.Progress = p
}

// Workspace adds local-file references, bounded stream staging and private
// durable outgoing journals to Agent. Nonseekable documents are cached once;
// selected local files are reopened and checked when sending or resuming.
type Workspace struct {
	withdrawals  sync.WaitGroup
	Agent        *Agent
	root         *os.Root
	mu           sync.Mutex
	stageMu      sync.Mutex
	jobs         map[string]*outgoingJob
	sources      map[string]StagedFile
	localSources map[string]localSource
	ctx          context.Context
	cancel       context.CancelFunc
	closed       bool
	stageCancel  context.CancelFunc
}

func (w *Workspace) Context() context.Context { return w.ctx }
func (w *Workspace) CancelPreparation() {
	w.mu.Lock()
	cancel := w.stageCancel
	w.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}
func (w *Workspace) Preparing() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.stageCancel != nil }

// Revoke stops every local task immediately and makes one bounded best-effort
// remote withdrawal pass. Logout must not wait a timeout for each old batch.
func (w *Workspace) Revoke() {
	w.mu.Lock()
	var done []chan struct{}
	for _, j := range w.jobs {
		if j.cancel != nil {
			j.cancel()
			done = append(done, j.done)
		}
	}
	w.mu.Unlock()
	for _, d := range done {
		<-d
	}
	w.mu.Lock()
	var tickets []outgoingRecord
	for _, j := range w.jobs {
		if j.record.Job.State == "paused" {
			j.record.Job.State = "cancelled"
			_ = writeRecord(w.root, "job-"+j.record.Job.ID+".json", j.record)
			tickets = append(tickets, j.record)
		}
	}
	w.mu.Unlock()
	ctx, cancel := context.WithTimeout(w.ctx, 2*time.Second)
	defer cancel()
	for _, r := range tickets {
		if ctx.Err() != nil {
			return
		}
		ip, err := netip.ParseAddr(r.Job.PeerIP)
		if err != nil {
			continue
		}
		s, err := w.Agent.Sender(ip)
		if err != nil {
			continue
		}
		_ = s.CancelBatch(ctx, r.Ticket)
		s.Close()
	}
}

func NewWorkspace(cfg AgentConfig) (*Workspace, error) {
	a, err := NewAgent(cfg)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(cfg.Directory)
	if err != nil {
		a.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	w := &Workspace{Agent: a, root: root, jobs: map[string]*outgoingJob{}, sources: map[string]StagedFile{}, localSources: map[string]localSource{}, ctx: ctx, cancel: cancel}
	d, err := root.Open(".")
	if err != nil {
		w.Close()
		return nil, err
	}
	entries, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		w.Close()
		return nil, err
	}
	var total int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, "source-") && strings.HasSuffix(name, ".json") {
			id := strings.TrimSuffix(strings.TrimPrefix(name, "source-"), ".json")
			if !validID(id) {
				continue
			}
			var record sourceRecord
			if err := readRecord(root, name, &record); err != nil {
				w.Close()
				return nil, err
			}
			s := record.StagedFile
			valid := s.ID == id && validName(s.Name) && s.Size >= 0 && s.Size <= cfg.MaxBytes-total && len(w.sources) < MaxBatchFiles
			if record.Local != nil {
				// Missing/changed originals must not prevent opening the file centre.
				// Revalidate the handle only when the user sends or resumes this source.
				valid = valid && record.Local.valid()
			} else {
				st, err := root.Stat("source-" + id + ".bin")
				valid = valid && err == nil && st.Size() == s.Size && st.Mode().IsRegular()
			}
			if !valid {
				w.Close()
				return nil, errors.New("invalid staged source or source quota exceeded")
			}
			total += s.Size
			w.sources[id] = s
			if record.Local != nil {
				w.localSources[id] = *record.Local
			}
		}
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "job-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(strings.TrimPrefix(name, "job-"), ".json")
		if !validID(id) {
			continue
		}
		var r outgoingRecord
		if err := readRecord(root, name, &r); err != nil {
			w.Close()
			return nil, err
		}
		if r.Job.ID != id || len(w.jobs) >= maxOutgoingRecords || (!r.Hidden && (w.visibleJobs() >= MaxBatchFiles || len(r.Job.Sources) < 1)) || len(r.Job.Sources) > MaxBatchFiles || (r.Hidden && (r.Job.State != "cancelled" || len(r.Job.Sources) != 0)) || (r.Ticket.ID != "" && (r.Ticket.Scope != cfg.Scope || !validID(r.Ticket.ID))) {
			w.Close()
			return nil, errors.New("invalid outgoing journal")
		}
		if r.Hidden && r.Withdrawn {
			if err := root.Remove(name); err != nil {
				w.Close()
				return nil, err
			}
			continue
		}
		for _, sid := range r.Job.Sources {
			if _, ok := w.sources[sid]; !ok {
				w.Close()
				return nil, errors.New("outgoing journal source unavailable")
			}
		}
		switch r.Job.State {
		case "completed", "paused":
			if r.Job.State == "paused" && r.Job.Error == context.Canceled.Error() {
				r.Job.Error = "" // Older journals treated an ordinary pause as an error.
			}
		case "cancelled":
			// Older journals marked local cancellation without peer confirmation.
			if !r.Withdrawn {
				for _, f := range r.Ticket.Files {
					if f.ID != "" || validID(f.Offer.ClientID) {
						r.Job.CancelPending = true
						break
					}
				}
			}
		case "sending":
			r.Job.State = "paused"
			r.Job.Error = "process restarted; resume to continue"
		default:
			w.Close()
			return nil, errors.New("invalid outgoing state")
		}
		w.jobs[id] = &outgoingJob{record: r}
		w.jobs[id].record.Job.RateBps = 0
		w.jobs[id].record.Job.RemainingSeconds = 0
	}
	// Remove only our random, unreferenced staging objects left by a process
	// dying before its metadata rename. No recursion or display-name paths.
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, "source-") && strings.HasSuffix(name, ".bin") {
			id := strings.TrimSuffix(strings.TrimPrefix(name, "source-"), ".bin")
			if validID(id) {
				if _, ok := w.sources[id]; !ok {
					if err := root.Remove(name); err != nil {
						w.Close()
						return nil, err
					}
				}
			}
		}
	}
	for _, j := range w.jobs {
		if j.record.Job.State == "cancelled" && j.record.Job.CancelPending {
			w.startWithdrawal(j)
		}
	}
	w.watchPausedJobs()
	return w, nil
}
func readRecord(root *os.Root, name string, out any) error {
	f, err := root.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewDecoder(io.LimitReader(f, 128<<10)).Decode(out)
}

func (w *Workspace) Stage(ctx context.Context, src io.Reader, name string, size int64) (StagedFile, error) {
	w.stageMu.Lock()
	defer w.stageMu.Unlock()
	var zero StagedFile
	if !validName(name) || size < -1 {
		return zero, errors.New("invalid source name or size")
	}
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return zero, errors.New("workspace closed")
	}
	var used int64
	for _, s := range w.sources {
		used += s.Size
	}
	count := len(w.sources)
	w.mu.Unlock()
	limit := w.Agent.cfg.MaxBytes - used
	if count >= MaxBatchFiles || size > limit {
		return zero, errors.New("staged source quota exceeded; clear completed tasks")
	}
	id := randomID()
	path := "source-" + id + ".bin"
	f, err := w.root.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return zero, err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			w.root.Remove(path)
		}
	}()
	stageCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	w.mu.Lock()
	w.stageCancel = cancel
	w.mu.Unlock()
	defer func() { w.mu.Lock(); w.stageCancel = nil; w.mu.Unlock() }()
	stop := context.AfterFunc(w.ctx, cancel)
	defer stop()
	// Native document pipes can block indefinitely. Cancellation must close
	// that already-authorized reader, not wait for its next successful Read.
	if closer, ok := src.(io.Closer); ok {
		stopRead := context.AfterFunc(stageCtx, func() { _ = closer.Close() })
		defer stopRead()
	}
	n, err := io.Copy(f, io.LimitReader(&contextReader{ctx: stageCtx, r: src}, limit+1))
	if err != nil {
		return zero, err
	}
	if n > limit || (size >= 0 && n != size) {
		return zero, errors.New("source exceeds staging limit or size changed")
	}
	if err := f.Sync(); err != nil {
		return zero, err
	}
	if err := f.Close(); err != nil {
		return zero, err
	}
	s := StagedFile{ID: id, Name: name, Size: n}
	if err := writeRecord(w.root, "source-"+id+".json", s); err != nil {
		return zero, err
	}
	w.mu.Lock()
	w.sources[id] = s
	w.mu.Unlock()
	ok = true
	return s, nil
}

func (w *Workspace) Staged() []StagedFile {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := []StagedFile{}
	for _, s := range w.sources {
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b StagedFile) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.ID, b.ID))
	})
	return out
}
func (w *Workspace) Jobs() []Job {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := []Job{}
	for _, j := range w.jobs {
		if j.record.Hidden {
			continue
		}
		job := j.record.Job
		if job.State != "sending" || time.Since(j.lastTime) > 3*time.Second {
			job.RateBps = 0
			job.RemainingSeconds = 0
		}
		job.Sources = append([]string(nil), job.Sources...)
		out = append(out, job)
	}
	// IDs are immutable; progress/state updates must not move a task on refresh.
	slices.SortFunc(out, func(a, b Job) int { return cmp.Compare(a.ID, b.ID) })
	return out
}

func (w *Workspace) Send(ip netip.Addr, ids []string, resume string) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return "", errors.New("workspace closed")
	}
	for _, j := range w.jobs {
		if j.cancel != nil {
			return "", errors.New("another batch is active")
		}
	}
	var j *outgoingJob
	if resume != "" {
		j = w.jobs[resume]
		if j == nil || j.record.Job.State != "paused" || j.record.Job.PeerIP != ip.String() {
			return "", errors.New("task cannot be resumed")
		}
		ids = j.record.Job.Sources
	} else {
		if len(ids) < 1 || len(ids) > MaxBatchFiles || w.visibleJobs() >= MaxBatchFiles || len(w.jobs) >= maxOutgoingRecords {
			return "", errors.New("batch or task limit exceeded")
		}
		id := randomID()
		j = &outgoingJob{record: outgoingRecord{Job: Job{ID: id, PeerIP: ip.String(), Sources: append([]string(nil), ids...), State: "paused"}}}
	}
	var sources []Source
	var opened []io.Closer
	closeFiles := func() {
		for _, f := range opened {
			f.Close()
		}
	}
	for _, id := range ids {
		s, ok := w.sources[id]
		if !ok {
			closeFiles()
			return "", errors.New("staged source unavailable")
		}
		var f io.ReadSeekCloser
		var err error
		if local, ok := w.localSources[id]; ok {
			f, err = local.open(s.Size)
		} else {
			f, err = w.root.Open("source-" + s.ID + ".bin")
		}
		if err != nil {
			closeFiles()
			return "", err
		}
		opened = append(opened, f)
		sources = append(sources, Source{Reader: f, Name: s.Name, Size: s.Size})
	}
	sender, err := w.Agent.Sender(ip)
	if err != nil {
		closeFiles()
		return "", err
	}
	ctx, cancel := context.WithCancel(w.ctx)
	j.cancel = cancel
	j.done = make(chan struct{})
	done := j.done
	j.record.Job.State = "sending"
	if j.record.Job.Progress.Transfer.Name == "" {
		j.record.Job.Progress = BatchProgress{Count: len(sources), Transfer: Transfer{Name: sources[0].Name, Size: sources[0].Size, State: "preparing"}}
	}
	j.report(BatchProgress{Count: len(sources), Preparation: &PreparationProgress{Phase: "hashing", Name: sources[0].Name, Count: len(sources), Size: sources[0].Size}})
	j.record.Job.RateBps = 0
	j.record.Job.RemainingSeconds = 0
	j.lastID = ""
	j.lastTime = time.Now()
	j.record.Job.Error = ""
	j.record.Job.StopReason = ""
	w.jobs[j.record.Job.ID] = j
	go func() {
		defer close(done)
		defer closeFiles()
		stopRead := context.AfterFunc(ctx, closeFiles)
		defer stopRead()
		defer sender.Close()
		// Local variable avoids sharing a mutable secret ticket with UI reads.
		ticket := j.record.Ticket
		err := sender.SendBatch(ctx, sources, &ticket, func(t BatchTicket) error {
			w.mu.Lock()
			defer w.mu.Unlock()
			b, _ := json.Marshal(t)
			if err := json.Unmarshal(b, &j.record.Ticket); err != nil {
				return err
			}
			return writeRecord(w.root, "job-"+j.record.Job.ID+".json", j.record)
		}, func(p BatchProgress) { w.mu.Lock(); j.report(p); w.mu.Unlock() })
		if err != nil && ctx.Err() != nil {
			// Cancellation closes source handles to unblock reads; do not report
			// that deliberate close as a changed or missing original file.
			err = ctx.Err()
		}
		w.mu.Lock()
		defer w.mu.Unlock()
		j.cancel = nil
		j.record.Job.RateBps = 0
		j.record.Job.RemainingSeconds = 0
		if err != nil {
			j.record.Job.State = "paused"
			j.record.Job.Error = err.Error()
			if errors.Is(err, context.Canceled) && errors.Is(ctx.Err(), context.Canceled) {
				j.record.Job.Error = ""
			}
			var stopped *peerStoppedError
			if errors.As(err, &stopped) {
				j.record.Job.State = "cancelled"
				j.record.Job.StopReason = stopped.Transfer.StopReason
				if j.record.Job.StopReason == "" {
					j.record.Job.StopReason = "receiver_cancelled"
				}
				if stopped.Transfer.State == "failed" {
					j.record.Job.StopReason = "receiver_failed"
				}
				j.record.Job.Error = ""
				// End the batch, including other waiting offers. Preserve completed files.
				j.record.Job.CancelPending = true
				w.startWithdrawal(j)
			}
		} else {
			j.record.Job.State = "completed"
		}
		if persistErr := writeRecord(w.root, "job-"+j.record.Job.ID+".json", j.record); persistErr != nil {
			j.record.Job.State = "paused"
			j.record.Job.Error = "cannot persist task result: " + persistErr.Error()
		}
	}()
	return j.record.Job.ID, nil
}

func (w *Workspace) Pause(id string) error {
	w.mu.Lock()
	j := w.jobs[id]
	if j == nil {
		w.mu.Unlock()
		return errors.New("unknown task")
	}
	cancel, done := j.cancel, j.done
	w.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
	return nil
}
func (w *Workspace) Cancel(id string) error {
	if err := w.Pause(id); err != nil {
		return err
	}
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return errors.New("workspace closed")
	}
	j := w.jobs[id]
	if j == nil {
		w.mu.Unlock()
		return errors.New("unknown task")
	}
	if j.record.Job.State == "completed" {
		w.mu.Unlock()
		return errors.New("completed task is retained")
	}
	if j.record.Withdrawn {
		w.mu.Unlock()
		return nil
	}
	previous := j.record.Job
	j.record.Job.State = "cancelled"
	j.record.Job.StopReason = "sender_cancelled"
	j.record.Job.Error = ""
	for _, f := range j.record.Ticket.Files {
		if f.ID != "" || validID(f.Offer.ClientID) {
			j.record.Job.CancelPending = true
			break
		}
	}
	persistErr := writeRecord(w.root, "job-"+id+".json", j.record)
	if persistErr != nil {
		j.record.Job = previous
	}
	if persistErr == nil && j.record.Job.CancelPending {
		w.startWithdrawal(j)
	}
	w.mu.Unlock()
	return persistErr
}
func (w *Workspace) ForgetJob(id string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	j := w.jobs[id]
	if j == nil {
		return errors.New("unknown task")
	}
	if j.cancel != nil || j.record.Job.State == "sending" {
		return errors.New("pause or cancel the task first")
	}
	if j.record.Job.CancelPending {
		// Removing local history must not discard an unacknowledged cancellation.
		// Keep only its ticket, without retaining the source or occupying a visible
		// task slot. The withdrawal worker removes this journal after acknowledgment.
		record := j.record
		record.Hidden = true
		record.Job.Sources = nil
		if err := writeRecord(w.root, "job-"+id+".json", record); err != nil {
			return err
		}
		j.record = record
		w.startWithdrawal(j)
		return nil
	}
	if err := w.root.Remove("job-" + id + ".json"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	delete(w.jobs, id)
	return nil
}
func (w *Workspace) ForgetSource(id string) error {
	w.stageMu.Lock()
	defer w.stageMu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.sources[id]; !ok {
		return errors.New("unknown source")
	}
	for _, j := range w.jobs {
		for _, sid := range j.record.Job.Sources {
			if sid == id {
				return errors.New("source is referenced by a task; remove its record first")
			}
		}
	}
	if err := w.root.Remove("source-" + id + ".json"); err != nil {
		return err
	}
	delete(w.sources, id)
	if _, local := w.localSources[id]; local {
		delete(w.localSources, id)
		return nil // Forget only the private reference, never the user's original.
	}
	return w.root.Remove("source-" + id + ".bin")
}
func (w *Workspace) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	w.cancel()
	var done []chan struct{}
	for _, j := range w.jobs {
		if j.cancel != nil {
			j.cancel()
			done = append(done, j.done)
		}
	}
	w.mu.Unlock()
	for _, d := range done {
		<-d
	}
	w.withdrawals.Wait()
	w.stageMu.Lock()
	defer w.stageMu.Unlock()
	err := w.Agent.Close()
	return errors.Join(err, w.root.Close())
}
