package filetransfer

// ShellPaste is a destination-side lease for a single authenticated batch.
// The Shell owns the final directory. Only verified files are exposed here;
// paths, tickets and network credentials never travel in the RDP clipboard.
import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"unicode/utf16"
)

const ShellPasteLimit int64 = 100 << 20

type ShellPaste struct {
	mu              sync.Mutex
	agent           *Agent
	ctx             context.Context
	cancel          context.CancelFunc
	files           []Received
	directory       string
	root            *os.Root
	cached          map[int]bool
	started, closed bool
}

func (a *Agent) NewShellPaste(ctx context.Context, directory, device, batch string) (*ShellPaste, error) {
	if !a.ClipboardReceiving() || !validID(batch) || device == "" {
		return nil, errors.New("file reception unavailable")
	}
	var files []Received
	for _, row := range a.List() {
		if row.DeviceKey == device && row.Transfer.Batch == batch {
			files = append(files, row)
		}
	}
	if err := validateShellBatch(files); err != nil {
		return nil, err
	}
	slices.SortFunc(files, func(a, b Received) int { return strings.Compare(a.Transfer.ID, b.Transfer.ID) })
	tmp, err := os.MkdirTemp(directory, "shell-paste-")
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(tmp)
	if err != nil {
		_ = os.Remove(tmp)
		return nil, err
	}
	child, cancel := context.WithCancel(ctx)
	return &ShellPaste{agent: a, ctx: child, cancel: cancel, files: files, directory: tmp, root: root, cached: map[int]bool{}}, nil
}
func validateShellBatch(files []Received) error {
	if len(files) < 1 || len(files) > 32 {
		return errors.New("incomplete or oversized clipboard batch")
	}
	total := int64(0)
	names := map[string]bool{}
	ids := map[string]bool{}
	for _, row := range files {
		t := row.Transfer
		name := strings.ToLower(t.Name)
		stem := strings.ToUpper(strings.SplitN(t.Name, ".", 2)[0])
		reserved := stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" || stem == "CONIN$" || stem == "CONOUT$"
		if len(stem) == 4 && (strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT")) {
			reserved = true
		}
		available := t.State == "waiting" || t.State == "completed" || t.State == "accepted" || t.State == "receiving" || t.State == "waiting_sender" || t.State == "verifying" || t.State == "committing" || t.State == "paused"
		if !t.Clipboard || t.BatchCount != len(files) || row.DeviceKey != files[0].DeviceKey || t.Batch != files[0].Transfer.Batch ||
			!validID(t.ID) || ids[t.ID] || !validName(t.Name) || len(utf16.Encode([]rune(t.Name))) >= 260 ||
			strings.ContainsAny(t.Name, `<>:"/\|?*`) || strings.HasSuffix(t.Name, ".") || strings.HasSuffix(t.Name, " ") || names[name] ||
			reserved || t.Size < 0 || t.Size > ShellPasteLimit-total || !available {
			return errors.New("clipboard batch does not match an available file offer")
		}
		total += t.Size
		names[name] = true
		ids[t.ID] = true
	}
	return nil
}
func (p *ShellPaste) Manifest() []byte {
	data := make([]byte, 4+592*len(p.files))
	binary.LittleEndian.PutUint32(data, uint32(len(p.files)))
	for i, row := range p.files {
		d := data[4+592*i:]
		t := row.Transfer
		binary.LittleEndian.PutUint32(d, 0x80000044) // UNICODE, FILESIZE, ATTRIBUTES; progress is owned by Calabi
		binary.LittleEndian.PutUint32(d[36:], 0x80)
		binary.LittleEndian.PutUint32(d[64:], uint32(uint64(t.Size)>>32))
		binary.LittleEndian.PutUint32(d[68:], uint32(t.Size))
		for j, u := range utf16.Encode([]rune(t.Name)) {
			binary.LittleEndian.PutUint16(d[72+j*2:], u)
		}
	}
	return data
}
func (p *ShellPaste) Begin() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.ctx.Err() != nil || !p.agent.ClipboardReceiving() {
		return errors.New("clipboard reception ended")
	}
	if p.started {
		return nil
	}
	var ids []string
	for _, row := range p.files {
		if row.Transfer.State == "waiting" {
			ids = append(ids, row.Transfer.ID)
		}
	}
	if len(ids) > 0 {
		if err := p.agent.Decide(ids, true); err != nil {
			return err
		}
	}
	p.started = true
	return nil
}

// Status revalidates the manifest against live records. A stale ID never
// selects another offer, nor can a receiver switch to another sender's batch.
func (p *ShellPaste) Status(index int) (ready bool, done, total int64, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.status(index)
}
func (p *ShellPaste) status(index int) (ready bool, done, total int64, err error) {
	if p.closed || p.ctx.Err() != nil || !p.agent.ClipboardReceiving() || index < 0 || index >= len(p.files) {
		return false, 0, 0, errors.New("clipboard reception ended")
	}
	live := p.agent.List()
	for i, expected := range p.files {
		found := false
		for _, row := range live {
			if row.DeviceKey != expected.DeviceKey || row.Transfer.ID != expected.Transfer.ID {
				continue
			}
			t, old := row.Transfer, expected.Transfer
			if t.Batch != old.Batch || t.Name != old.Name || t.Size != old.Size || t.SHA256 != old.SHA256 {
				return false, 0, 0, errors.New("clipboard offer changed")
			}
			if t.State == "cancelled" || t.State == "failed" || t.State == "rejected" {
				return false, 0, 0, errors.New("file transfer stopped")
			}
			total += t.Size
			done += min(t.Size, max(0, t.Offset))
			if i == index {
				ready = t.State == "completed"
			}
			found = true
			break
		}
		if !found {
			return false, 0, 0, errors.New("clipboard offer disappeared")
		}
	}
	return
}

// Read uses bounded private IPC chunks, never JSON/base64 file bodies through
// the machine service. Export checksum verification precedes the first byte.
func (p *ShellPaste) Read(index int, offset int64, count int) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ready, _, _, err := p.status(index)
	if err != nil {
		return nil, err
	}
	if !ready || !p.started {
		return nil, errors.New("verified file not ready")
	}
	size := p.files[index].Transfer.Size
	if offset < 0 || offset > size || count < 0 || count > 64*1024 {
		return nil, errors.New("invalid clipboard range")
	}
	name := fmt.Sprintf("%d.bin", index)
	if !p.cached[index] {
		f, err := p.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		err = p.agent.CopyCompleted(p.ctx, p.files[index].Transfer.ID, f)
		closeErr := f.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			_ = p.root.Remove(name)
			return nil, err
		}
		p.cached[index] = true
	}
	f, err := p.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data := make([]byte, min(int64(count), size-offset))
	_, err = f.ReadAt(data, offset)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return data, nil
}
func (p *ShellPaste) Cancel() {
	p.cancel() // interrupts checksum export before taking the cache mutex
	for _, row := range p.files {
		_ = p.agent.Cancel(row.Transfer.ID)
	}
}
func (p *ShellPaste) Close() {
	p.Cancel()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	for i := range p.cached {
		_ = p.root.Remove(fmt.Sprintf("%d.bin", i))
	}
	_ = p.root.Close()
	_ = os.Remove(filepath.Clean(p.directory))
}

// Batch IDs exist during hashing, before any remote offers. Only the first
// status response after ALL offers were acknowledged makes a marker usable.
func ShellOfferReady(p BatchProgress) bool {
	return p.Batch != "" && p.Preparation == nil && p.Transfer.ID != "" && p.Transfer.Clipboard && p.Transfer.State == "waiting"
}
