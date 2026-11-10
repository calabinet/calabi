package mesh

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"math"
	"math/rand"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// Test-only impairment after WG decapsulation. Datagrams in one frame can be
// in flight together. Charge all bytes (including dropped ones) at the configured
// per-direction rate; propagation delay is not multiplied by the fragment count.
type returnSlot struct {
	end time.Time
	ack bool
}
type echoLink struct {
	loaded, priority bool
	queue            []*returnSlot
	video            []byte
	waitMax, busy    time.Duration
	acks, contended  int
	mu               sync.Mutex
	t                *testing.T
	pair             *probeBusinessPair
	rng              *rand.Rand
	weak             bool
	dropNextInput    bool
	dropNextAck      bool
	next             [2]time.Time
	packets, drops   [2]int
}
type echoDelivery struct {
	data []byte
	due  time.Time
	slot *returnSlot
	link *echoLink
}

func (l *echoLink) enqueue(from int, b []byte) echoDelivery {
	return l.enqueueWithLoss(from, b, false)
}
func (l *echoLink) enqueueWithLoss(from int, b []byte, forced bool) echoDelivery {
	l.mu.Lock()
	defer l.mu.Unlock()
	received := desktopHop(l.t, l.pair, from, b, time.After(4*time.Second))
	now := time.Now()
	due := now
	var slot *returnSlot
	if l.weak {
		cost := time.Duration(len(b)+28) * 8 * time.Second / 4_000_000
		if l.loaded && from == 1 {
			ack := bytes.HasPrefix(b, []byte("ack "))
			slot = l.schedule(now, cost, ack)
			if !ack && len(b) > 1000 {
				l.video = b
			}
		} else {
			if now.Before(l.next[from]) {
				now = l.next[from]
			}
			l.next[from] = now.Add(time.Duration(len(b)+28) * 8 * time.Second / 4_000_000)
			due = l.next[from].Add(40 * time.Millisecond)
		}
		l.packets[from]++
		drop := l.rng.Float64() < 0.01 || forced
		if from == 0 && l.dropNextInput && strings.Contains(string(b), " char ") {
			drop = true
			l.dropNextInput = false
		}
		if from == 1 && l.dropNextAck && bytes.HasPrefix(b, []byte("ack ")) {
			drop = true
			l.dropNextAck = false
		}
		if drop {
			l.drops[from]++
			received = nil
		}
	}
	return echoDelivery{data: received, due: due, slot: slot, link: l}
}
func (d echoDelivery) receive() []byte {
	for d.slot != nil {
		d.link.mu.Lock()
		due := d.slot.end.Add(40 * time.Millisecond)
		d.link.mu.Unlock()
		if delay := time.Until(due); delay > 0 {
			time.Sleep(delay)
			continue
		}
		return d.data
	}
	time.Sleep(time.Until(d.due))
	return d.data
}

// Keep serialization non-preemptive: an ACK can pass only video datagrams
// whose transmission has not started. Propagation is outside the queue.
func (l *echoLink) schedule(now time.Time, cost time.Duration, ack bool) *returnSlot {
	for len(l.queue) > 0 && !l.queue[0].end.After(now) {
		l.queue = l.queue[1:]
	}
	pos := len(l.queue)
	if ack {
		l.acks++
		videoAhead := false
		for i, s := range l.queue {
			if !s.ack {
				videoAhead = true
			}
			if l.priority && i > 0 && !s.ack {
				pos = i
				break
			}
		}
		if videoAhead {
			l.contended++
		}
	}
	start := now
	if pos > 0 {
		start = l.queue[pos-1].end
	}
	if ack {
		l.waitMax = max(l.waitMax, start.Sub(now))
	}
	slot := &returnSlot{end: start.Add(cost), ack: ack}
	for _, s := range l.queue[pos:] {
		s.end = s.end.Add(cost)
	}
	l.queue = append(l.queue, nil)
	copy(l.queue[pos+1:], l.queue[pos:])
	l.queue[pos] = slot
	l.busy += cost
	return slot
}

type frameStages struct {
	pushed                                             bool
	request, capture, send, firstPass, received, paint time.Time
	fullBytes, wireBytes                               int
}
type echoBench struct {
	wakeup                   chan struct{}
	anchorID                 uint32
	anchorHost, anchorViewer []byte
	skippedRepair            int
	sliding                  bool
	stages                   frameStages
	delta                    bool
	baseID                   uint32
	hostBase, viewerBase     []byte
	hostMu, viewerMu         sync.Mutex
	t                        *testing.T
	link                     echoLink
	host, viewer             desktopPipe
	paints, framesLost       int
	frameID                  uint32
	repair                   bool
	recovered                int
}

func (b *echoBench) send(msg string) string {
	p := b.link.enqueue(0, []byte(msg)).receive()
	if p == nil {
		return "lost"
	}
	return inputIPC(b.t, b.host, string(p))
}
func (b *echoBench) note() []string {
	f := strings.Fields(inputIPC(b.t, b.host, "inspect-note"))
	if len(f) != 12 {
		b.t.Fatal("invalid local Notepad diagnostic")
	}
	raw, err := base64.StdEncoding.DecodeString(f[5])
	if err != nil {
		b.t.Fatal(err)
	}
	f[5] = string(raw)
	return f
}

// A request/heartbeat crosses the impaired forward path. Only complete
// JPEGs, including successfully repaired ones, can be painted or credited.
func (b *echoBench) frame() (image.Image, time.Time) {
	t := b.t
	t.Helper()
	b.stages = frameStages{request: time.Now()}
	request := []byte("frame")
	if b.delta {
		request = binary.BigEndian.AppendUint32(request, b.baseID)
	}
	var got []byte
	select {
	case <-b.wakeup:
		b.stages.pushed = true
	default:
		d := b.link.enqueue(0, request)
		if b.wakeup == nil {
			got = d.receive()
		} else {
			select {
			case <-b.wakeup:
				b.stages.pushed = true
			case <-time.After(time.Until(d.due)):
				got = d.data
			}
		}
	}
	if !b.stages.pushed && got == nil {
		return nil, time.Time{}
	}
	b.stages.capture = time.Now()
	src := b.capture(!b.stages.pushed)
	if len(src) == 0 {
		return nil, time.Time{}
	}
	n := uint32(len(src))

	b.frameID++
	payload := src
	if b.delta {
		if b.stages.pushed {
			payload = packFrame(src, b.anchorHost, b.anchorID)
		} else {
			if len(got) != 9 || binary.BigEndian.Uint32(got[5:]) != b.baseID {
				t.Fatal("unexpected base request")
			}
			if b.wakeup != nil {
				b.anchorID = b.baseID
				b.anchorHost = b.hostBase
				b.anchorViewer = b.viewerBase
			}
			payload = packFrame(src, b.hostBase, b.baseID)
		}
	}
	b.stages.send = time.Now()
	b.stages.fullBytes = len(src)
	b.stages.wireBytes = len(payload)
	dst := b.transfer(payload)
	b.stages.received = time.Now()
	if dst == nil {
		b.framesLost++
		return nil, time.Time{}
	}
	if b.delta {
		var ok bool
		if b.stages.pushed {
			dst, ok = unpackFrame(dst, b.anchorViewer, b.anchorID)
		} else {
			dst, ok = unpackFrame(dst, b.viewerBase, b.baseID)
		}
		if !ok {
			t.Fatal("invalid frame delta")
		}
	}
	if !bytes.Equal(src, dst) {
		t.Fatal("corrupt frame")
	}
	b.viewerMu.Lock()
	defer b.viewerMu.Unlock()
	if err := binary.Write(b.viewer.in, binary.LittleEndian, n); err != nil {
		t.Fatal(err)
	}
	if _, err := b.viewer.in.Write(dst); err != nil {
		t.Fatal(err)
	}
	var ack uint32
	if err := binary.Read(b.viewer.out, binary.LittleEndian, &ack); err != nil {
		t.Fatal(err)
	}
	at := time.Now()
	b.stages.paint = at
	if b.delta {
		b.hostBase = src
		b.viewerBase = dst
		b.baseID = b.frameID
	}
	b.paints++
	if int(ack) != b.paints {
		t.Fatal("missing paint acknowledgement")
	}
	img, err := jpeg.Decode(bytes.NewReader(dst))
	if err != nil {
		t.Fatal(err)
	}
	return img, at
}
func (b *echoBench) capture(heartbeat bool) []byte {
	t := b.t
	b.hostMu.Lock()
	defer b.hostMu.Unlock()
	if heartbeat {
		inputIPC(t, b.host, "status")
	}
	if err := binary.Write(b.host.in, binary.LittleEndian, uint32(0)); err != nil {
		t.Fatal(err)
	}
	var n uint32
	if err := binary.Read(b.host.out, binary.LittleEndian, &n); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		return nil
	}
	if n > 2_000_000 {
		t.Fatal("oversized JPEG")
	}
	src := make([]byte, n)
	if _, err := io.ReadFull(b.host.out, src); err != nil {
		t.Fatal(err)
	}
	return src
}
func (b *echoBench) transfer(src []byte) []byte {
	n := uint32(len(src))
	var flight []echoDelivery
	var originals [][]byte
	for off := 0; off < len(src); {
		size := min(1100, len(src)-off)
		part := make([]byte, 12+size)
		binary.BigEndian.PutUint32(part, b.frameID)
		binary.BigEndian.PutUint32(part[4:], uint32(off))
		binary.BigEndian.PutUint32(part[8:], n)
		copy(part[12:], src[off:off+size])
		originals = append(originals, part)
		flight = append(flight, b.link.enqueue(1, part))
		off += size
	}
	dst := make([]byte, n)
	var missing []int
	accept := func(i int, v []byte) {
		if len(v) != 12+min(1100, len(dst)-i*1100) || binary.BigEndian.Uint32(v) != b.frameID || binary.BigEndian.Uint32(v[4:]) != uint32(i*1100) || binary.BigEndian.Uint32(v[8:]) != n {
			b.t.Fatal("invalid received fragment")
		}
		copy(dst[i*1100:], v[12:])
	}
	for i, d := range flight {
		if v := d.receive(); v != nil {
			accept(i, v)
		} else {
			missing = append(missing, i)
		}
	}
	b.stages.firstPass = time.Now()
	if len(missing) > 0 {
		if !b.stages.pushed && len(b.wakeup) > 0 {
			b.skippedRepair++
			return nil
		}
		if !b.repair || len(missing) == len(flight) || len(missing) > 500 {
			return nil
		}
		// The receiver requests only absent offsets, once per frame.
		req := binary.BigEndian.AppendUint32(nil, b.frameID)
		for _, i := range missing {
			req = binary.BigEndian.AppendUint16(req, uint16(i))
		}
		got := b.link.enqueue(0, req).receive()
		if got == nil {
			return nil
		}
		if len(got) < 6 || len(got)%2 != 0 || binary.BigEndian.Uint32(got) != b.frameID {
			b.t.Fatal("invalid repair request")
		}
		var repairs []echoDelivery
		for j := 4; j < len(got); j += 2 {
			i := int(binary.BigEndian.Uint16(got[j:]))
			if i >= len(originals) {
				b.t.Fatal("invalid requested index")
			}
			repairs = append(repairs, b.link.enqueue(1, originals[i]))
		}
		for j, d := range repairs {
			v := d.receive()
			if v == nil {
				return nil
			}
			accept(missing[j], v)
		}
		b.recovered++
	}
	return dst
}
func (b *echoBench) image() image.Image {
	for until := time.Now().Add(10 * time.Second); time.Now().Before(until); {
		if img, _ := b.frame(); img != nil {
			return img
		}
		time.Sleep(100 * time.Millisecond)
	}
	b.t.Fatal("no complete reference frame")
	return nil
}

// The newly appended glyph has ink across multiple columns. Compare against
// the same on-screen rectangle before typing; ignore the narrow caret edge.
func echoInk(before, after image.Image, region string) bool {
	var x, y, w, h int
	if _, err := fmt.Sscan(region, &x, &y, &w, &h); err != nil || w <= 0 || h <= 0 {
		return false
	}
	sx, sy := float64(after.Bounds().Dx())/float64(w), float64(after.Bounds().Dy())/float64(h)
	cols, pixels := 0, 0
	for col := int(math.Ceil(float64(x+2) * sx)); col < int(float64(x+15)*sx); col++ {
		dirty := false
		for row := int(float64(y) * sy); row < int(float64(y+23)*sy); row++ {
			lum := func(i image.Image) int { return int(color.GrayModel.Convert(i.At(col, row)).(color.Gray).Y) }
			if lum(before)-lum(after) > 42 {
				pixels++
				dirty = true
			}
		}
		if dirty {
			cols++
		}
	}
	return cols >= 3 && pixels >= 5
}
func (b *echoBench) samples(count int) {
	t := b.t
	before := b.image()
	var values []time.Duration
	missing := 0
	for attempts := 0; len(values) < count && attempts < count+10; attempts++ {
		initial := b.note()[5]
		start := time.Now()
		key := inputIPC(t, b.viewer, "echo-key")
		if !strings.Contains(key, " char ") {
			t.Fatal("missing viewer input")
		}
		result := b.send(key)
		if result == "lost" {
			missing++
			continue
		}
		if result != "ok" {
			t.Fatalf("key: %s", result)
		}
		var region string
		for until := start.Add(time.Second); time.Now().Before(until); {
			if b.note()[5] == initial+"测" {
				region = inputIPC(t, b.host, "echo-region")
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if region == "" {
			t.Fatal("Notepad did not append glyph")
		}
		found := false
		for time.Since(start) < 10*time.Second {
			img, at := b.frame()
			if img != nil && echoInk(before, img, region) {
				values = append(values, at.Sub(start))
				before = img
				found = true
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !found {
			t.Fatal("new glyph was not verified in painted pixels")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(values) != count {
		t.Fatal("insufficient measured keys")
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	t.Logf("weak=%t confirmed=%d lost_keys=%d p50=%v p95=%v max=%v", b.link.weak, count, missing, values[(count-1)/2], values[(count*95+99)/100-1], values[count-1])
}
func (b *echoBench) waitControl(want bool) {
	for until := time.Now().Add(2 * time.Minute); time.Now().Before(until); {
		b.frame()
		f := b.note()
		if (f[1] == "1") == want && (want || f[2] == "revoke") {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	b.t.Fatal("authorization timeout")
}
func (b *echoBench) late(disconnect bool) {
	t := b.t
	f := b.note()
	grant := f[0]
	inputIPC(t, b.viewer, "grant "+grant)
	// Cross the WG path now, retaining the actual received payload in an
	// application delivery backlog. Never manufacture a stale request after revoke.
	var queued []echoDelivery
	for len(queued) < 6 {
		key := inputIPC(t, b.viewer, "echo-key")
		if !strings.HasPrefix(key, grant+" char ") {
			t.Fatal("incorrect queued grant")
		}
		d := b.link.enqueue(0, []byte(key))
		if d.data != nil {
			queued = append(queued, d)
		}
	}
	snapshot := func(f []string) string { return strings.Join(f[5:8], "/") }
	before := snapshot(f)
	if disconnect {
		// No remote packets are delivered while blackholed, even heartbeats.
		for b.send("note") == "lost" {
		} // last legitimate heartbeat
		start := time.Now()
		for time.Since(start) < 2*time.Second && b.note()[2] != "timeout" {
			time.Sleep(10 * time.Millisecond)
		}
		if b.note()[2] != "timeout" {
			t.Fatal("failed to invalidate lease")
		}
		t.Logf("blackhole detected after %v", time.Since(start))
	} else {
		t.Log("backlog armed: click revoke now")
		inputIPC(t, b.host, "echo-backlog")
		b.waitControl(false)
	}
	for _, d := range queued {
		if inputIPC(t, b.host, string(d.receive())) != "denied" {
			t.Fatal("late input accepted")
		}
	}
	time.Sleep(150 * time.Millisecond)
	if snapshot(b.note()) != before {
		t.Fatal("late input changed Notepad text/selection")
	}
	t.Logf("disconnect=%t released_backlog=%d applied=0 text_and_selection_unchanged", disconnect, len(queued))
}
func TestAssistWeakEchoP0(t *testing.T) {
	exe := os.Getenv("CALABI_ASSIST_P0_DESKTOP")
	if exe == "" || os.Getenv("CALABI_ASSIST_WEAK") != "1" {
		t.Skip("requires live local consent")
	}
	for _, path := range []string{PathDirect, PathRelay} {
		t.Run(path, func(t *testing.T) {
			p := assistPair(t, path)
			b := echoBench{t: t, link: echoLink{t: t, pair: p, rng: rand.New(rand.NewSource(47))}}
			b.viewer = startDesktopPipe(t, exe, "view-note", path)
			b.host = startDesktopPipe(t, exe, "send-note", path)
			if img, _ := b.frame(); img != nil {
				t.Fatal("unauthorized pixels")
			}
			for b.paints == 0 {
				b.frame()
				time.Sleep(100 * time.Millisecond)
			}
			if b.send("0 char 27979 0") != "denied" {
				t.Fatal("unauthorized key")
			}
			b.waitControl(true)
			inputIPC(t, b.viewer, "grant "+b.note()[0])
			if b.send("echo-prepare") != "ok" {
				t.Fatal("failed to activate dedicated Notepad")
			}
			bind := p.devices[1].bind
			direct, relay := bind.txDirect.Load(), bind.txRelay.Load()
			if os.Getenv("CALABI_ASSIST_KEYS") == "1" {
				if os.Getenv("CALABI_ASSIST_LIVE_BURST") == "1" {
					b.liveBursts()
				} else if os.Getenv("CALABI_ASSIST_BURST") == "1" {
					b.burstKeys()
				} else {
					b.reliableKeys()
				}
				if path == PathDirect && (bind.txDirect.Load() <= direct || bind.txRelay.Load() != relay) || path == PathRelay && (bind.txRelay.Load() <= relay || bind.txDirect.Load() != direct) {
					t.Fatal("unexpected transport")
				}
				return
			}
			b.samples(8)
			b.link.weak = true
			b.repair = os.Getenv("CALABI_ASSIST_REPAIR") == "1"
			if b.repair {
				before := b.note()
				b.link.dropNextInput = true
				if b.send(inputIPC(t, b.viewer, "echo-key")) != "lost" || b.link.dropNextInput {
					t.Fatal("targeted drop missed input")
				}
				b.image()
				if strings.Join(b.note()[5:8], "/") != strings.Join(before[5:8], "/") {
					t.Fatal("dropped key changed Notepad")
				}
				t.Log("targeted key lost: text and selection unchanged after next complete frame")
			}
			b.samples(20)
			t.Logf("repair=%t recovered_frames=%d", b.repair, b.recovered)
			b.late(false)
			b.waitControl(true)
			b.late(true)
			direct, relay = bind.txDirect.Load()-direct, bind.txRelay.Load()-relay
			t.Logf("impaired_packets=%v dropped=%v incomplete_frames=%d direct_tx=%d relay_tx=%d", b.link.packets, b.link.drops, b.framesLost, direct, relay)
			if (path == PathDirect && (direct == 0 || relay != 0)) || (path == PathRelay && (relay == 0 || direct != 0)) || (b.framesLost == 0 && b.recovered == 0) {
				t.Fatal("missing path/loss evidence")
			}
		})
	}
}

func TestAssistWeakFrameRepair(t *testing.T) {
	for _, path := range []string{PathDirect, PathRelay} {
		t.Run(path, func(t *testing.T) {
			p := assistPair(t, path)
			src := make([]byte, 60_017)
			rand.New(rand.NewSource(9)).Read(src)
			var baseline int
			for _, repair := range []bool{false, true} {
				b := echoBench{t: t, repair: repair, link: echoLink{t: t, pair: p, weak: true, rng: rand.New(rand.NewSource(47))}}
				var complete int
				for i := 0; i < 12; i++ {
					b.frameID++
					got := b.transfer(src)
					if got != nil {
						if !bytes.Equal(got, src) {
							t.Fatal("corrupt reassembly")
						}
						complete++
					}
				}
				t.Logf("repair=%t complete=%d/12 recovered=%d", repair, complete, b.recovered)
				if !repair {
					baseline = complete
				} else if b.recovered == 0 || complete <= baseline {
					t.Fatal("repair did not improve complete frame delivery")
				}
			}
		})
	}
}

// One outstanding character per grant. Every attempt reuses the original
// grant and sequence. Both the input and its response traverse the mesh.
func (b *echoBench) keyAttempt(key string) string {
	deadline := time.Now().Add(180 * time.Millisecond)
	if request := b.link.enqueue(0, []byte(key)).receive(); request != nil {
		reply := inputIPC(b.t, b.host, string(request))
		if ack := b.link.enqueue(1, []byte(reply)).receive(); ack != nil {
			return string(ack)
		}
	}
	time.Sleep(time.Until(deadline))
	return "timeout"
}

func (b *echoBench) deliverKey(key string) (string, int) {
	for attempt := 1; attempt <= 4; attempt++ {
		if reply := b.keyAttempt(key); reply != "timeout" {
			return reply, attempt
		}
	}
	b.t.Fatal("key unconfirmed after retry budget")
	return "", 4
}

func (b *echoBench) reliableKeys() {
	t := b.t
	b.link.weak = true
	b.repair = true
	initial := b.note()[5]
	grant := b.note()[0]
	for i := 1; i <= 2; i++ {
		key := inputIPC(t, b.viewer, "echo-key")
		b.link.dropNextInput = i == 1
		b.link.dropNextAck = i == 2
		reply, attempts := b.deliverKey(key)
		if reply != fmt.Sprintf("ack %s %d", grant, i) || attempts < 2 || b.link.dropNextAck || b.link.dropNextInput {
			t.Fatalf("unexpected acknowledgement: %q attempts=%d", reply, attempts)
		}
		b.image()
		if b.note()[5] != initial+strings.Repeat("测", i) {
			t.Fatal("missing or duplicated character")
		}
		t.Logf("seq=%d attempts=%d confirmed; Notepad appended exactly one character", i, attempts)
	}
	key := inputIPC(t, b.viewer, "echo-key")
	b.link.dropNextInput = true
	if b.keyAttempt(key) != "timeout" || b.link.dropNextInput {
		t.Fatal("expected pending key")
	}
	inputIPC(t, b.host, "echo-backlog")
	b.waitControl(false)
	checkDenied := func(stale string) {
		before := strings.Join(b.note()[5:8], "/")
		if reply, _ := b.deliverKey(stale); reply != "denied" {
			t.Fatalf("stale key: %s", reply)
		}
		time.Sleep(100 * time.Millisecond)
		if strings.Join(b.note()[5:8], "/") != before {
			t.Fatal("stale input changed text or selection")
		}
	}
	checkDenied(key)
	b.waitControl(true)
	checkDenied(key)
	inputIPC(t, b.viewer, "grant "+b.note()[0])
	fresh := inputIPC(t, b.viewer, "echo-key")
	if reply, _ := b.deliverKey(fresh); reply != "ack "+b.note()[0]+" 1" {
		t.Fatalf("new grant key: %s", reply)
	}
	b.image()
	if b.note()[5] != initial+"测测测" {
		t.Fatal("new grant failed to append exactly once")
	}
	next := inputIPC(t, b.viewer, "echo-key")
	b.link.dropNextInput = true
	if b.keyAttempt(next) != "timeout" || b.link.dropNextInput {
		t.Fatal("expected pending key before disconnect")
	}
	for until := time.Now().Add(2 * time.Second); b.note()[2] != "timeout"; {
		if time.Now().After(until) {
			t.Fatal("lease did not expire")
		}
		time.Sleep(10 * time.Millisecond)
	}
	checkDenied(next)
	t.Log("retries denied after revoke, regrant and lease expiry; text and selection unchanged")
}

func (b *echoBench) burstKeys() {
	t := b.t
	b.link.weak = true
	b.repair = true
	initial := b.note()[5]
	grant := b.note()[0]
	start := func(chars string) {
		if inputIPC(t, b.viewer, "burst "+base64.StdEncoding.EncodeToString([]byte(chars))) != "ok" {
			t.Fatal("viewer burst not started")
		}
	}
	pop := func() string {
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
			if key := inputIPC(t, b.viewer, "burst-pop"); key != "empty" {
				return key
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatal("viewer queue starved")
		return ""
	}
	send := func(seq int) {
		key := pop()
		if reply, _ := b.deliverKey(key); reply != fmt.Sprintf("ack %s %d", grant, seq) {
			t.Fatalf("wrong acknowledgement %s", reply)
		}
		if seq%4 == 1 {
			b.send("note")
		}
	}
	state := func() (produced, queued, peak, typing, drain int) {
		if _, err := fmt.Sscan(inputIPC(t, b.viewer, "burst-state"), &produced, &queued, &peak, &typing, &drain); err != nil {
			t.Fatal(err)
		}
		return
	}
	const full = "春A夏B秋C冬D甲1乙2丙3丁4山E水F云G月H"
	start(full)
	n := len([]rune(full))
	window := os.Getenv("CALABI_ASSIST_WINDOW") == "4"
	if window {
		for first := 1; first <= n; first += 4 {
			keys := []string{pop(), pop(), pop(), pop()}
			b.keyWindow(keys, grant, first)
			if first+3 < n {
				b.send("note")
			}
		}
	} else {
		for seq := 1; seq <= n; seq++ {
			if seq == 3 {
				b.link.dropNextInput = true
			}
			if seq == 7 {
				b.link.dropNextAck = true
			}
			send(seq)
		}
	}
	produced, queued, peak, typing, drain := state()
	if produced != n || queued != 0 || peak < 2 || b.note()[5] != initial+full {
		t.Fatal("burst delivery or queue mismatch")
	}
	t.Logf("chars=%d produced_in_ms=%d peak_unsent=%d last_char_to_final_ack_ms=%d", n, typing, peak, drain)
	const cut = "零一二三四五六七八九十甲乙丙丁戊"
	start(cut)
	for i := 1; i <= 4; i++ {
		send(n + i)
	}
	pending := []string{pop()}
	b.link.dropNextInput = true
	if b.keyAttempt(pending[0]) != "timeout" {
		t.Fatal("expected pending key")
	}
	if window {
		for i := 0; i < 3; i++ {
			key := pop()
			pending = append(pending, key)
			if reply, _ := b.deliverKey(key); reply != fmt.Sprintf("ack %s %d", grant, n+4) {
				t.Fatal("out of order key applied early", reply)
			}
		}
		if inputIPC(t, b.host, "inspect-buffer") != "3" {
			t.Fatal("receiver backlog not armed")
		}
	}
	_, queued, _, _, _ = state()
	if queued < 2 {
		t.Fatal("no backlog at revoke prompt")
	}
	inputIPC(t, b.host, "echo-backlog")
	b.waitControl(false)
	if window && inputIPC(t, b.host, "inspect-buffer") != "0" {
		t.Fatal("buffer survived revocation")
	}
	_, queued, _, _, _ = state()
	expected := initial + full + string([]rune(cut)[:4])
	if b.note()[5] != expected {
		t.Fatal("unexpected text at revoke")
	}
	// Leave the viewer queue intact until the next grant to exercise epoch cleanup.
	b.waitControl(true)
	grant = b.note()[0]
	if inputIPC(t, b.viewer, "grant "+grant) != "" || inputIPC(t, b.viewer, "burst-pop") != "empty" {
		t.Fatal("old queued input survived new grant")
	}
	for _, key := range pending {
		if reply, _ := b.deliverKey(key); reply != "denied" {
			t.Fatal("old in-flight key accepted")
		}
	}
	start("新Z")
	send(1)
	send(2)
	b.image()
	if b.note()[5] != expected+"新Z" {
		t.Fatal("old text leaked or new text missing")
	}
	t.Logf("regrant: unsent_discarded=%d pending_denied=%d fresh_chars=2 final_text_exact", queued, len(pending))
}

// Use a bounded flight of four. Only a cumulative ACK for the current grant
// advances the confirmed prefix. Retry the outstanding suffix after timeout.
func (b *echoBench) keyWindow(keys []string, grant string, first int) {
	t := b.t
	confirmed := first - 1
	groupStart := 1
	if os.Getenv("CALABI_ASSIST_DELTA") == "1" {
		groupStart = 1 + 24*((first-1)/24)
	}
	end := first + len(keys) - 1
	for attempt := 0; attempt < 4; attempt++ {
		deadline := time.Now().Add(180 * time.Millisecond)
		var requests []echoDelivery
		for seq := confirmed + 1; seq <= end; seq++ {
			key := keys[seq-first]
			f := strings.Fields(key)
			if len(f) != 4 || f[0] != grant || f[3] != fmt.Sprint(seq) {
				t.Fatal("unexpected viewer sequence")
			}
			requests = append(requests, b.link.enqueueWithLoss(0, []byte(key), attempt == 0 && seq == groupStart+2))
		}
		var replies []echoDelivery
		// Deliver the actual four datagrams in reverse on the first flight.
		for i := 0; i < len(requests); i++ {
			j := i
			if first == groupStart && attempt == 0 {
				j = len(requests) - 1 - i
			}
			if data := requests[j].receive(); data != nil {
				reply := b.hostCommand(string(data))
				if first == groupStart && attempt == 0 && j > 0 && reply != fmt.Sprintf("ack %s %d", grant, groupStart-1) {
					t.Fatal("out-of-order character confirmed prematurely")
				}
				replies = append(replies, b.link.enqueueWithLoss(1, []byte(reply), attempt == 0 && confirmed+1+j == groupStart+6))
			}
		}
		for _, r := range replies {
			if ack := r.receive(); ack != nil {
				var epoch string
				var seq int
				if _, err := fmt.Sscanf(string(ack), "ack %s %d", &epoch, &seq); err != nil || epoch != grant || seq < 0 || seq > end {
					t.Fatalf("invalid cumulative ack: %s", ack)
				}
				confirmed = max(confirmed, seq)
			}
		}
		if confirmed == end {
			return
		}
		time.Sleep(time.Until(deadline))
	}
	t.Fatal("window retry budget exhausted")
}

func (b *echoBench) hostCommand(msg string) string {
	b.hostMu.Lock()
	defer b.hostMu.Unlock()
	return inputIPC(b.t, b.host, msg)
}
func (b *echoBench) viewerCommand(msg string) string {
	b.viewerMu.Lock()
	defer b.viewerMu.Unlock()
	return inputIPC(b.t, b.viewer, msg)
}

func (b *echoBench) liveBursts() {
	b.link.weak = true
	b.repair = true
	grant := b.note()[0]
	initial := b.note()[5]
	rounds := 5
	compare := os.Getenv("CALABI_ASSIST_DELTA") == "1"
	if compare {
		rounds = 10
	}
	loaded := os.Getenv("CALABI_ASSIST_ACK_PRIORITY") == "1"
	if loaded {
		rounds = 24
	}
	for round := 0; round < rounds; round++ {
		b.delta = compare && round%2 == 1
		if loaded {
			b.delta = true
			b.link.loaded = true
			b.link.priority = round%4 == 1 || round%4 == 2
			if os.Getenv("CALABI_ASSIST_SLIDING") == "1" {
				b.sliding = b.link.priority
				b.link.priority = true
			}
			if os.Getenv("CALABI_ASSIST_PUSH") == "1" {
				b.wakeup = nil
				if round%4 == 1 || round%4 == 2 {
					b.wakeup = make(chan struct{}, 1)
				}
				b.sliding = true
				b.link.priority = true
				b.anchorID = 0
				b.anchorHost = nil
				b.anchorViewer = nil
				b.skippedRepair = 0
			}
			b.link.waitMax = 0
			b.link.contended = 0
			b.link.acks = 0
			b.link.video = nil
			b.link.rng = rand.New(rand.NewSource(int64(47 + round/2)))
		}
		b.baseID = 0
		b.hostBase = nil
		b.viewerBase = nil
		b.liveBurst(round, grant, initial)
		if b.wakeup != nil {
			b.t.Logf("superseded_incomplete_frames=%d", b.skippedRepair)
		}
	}
}

// The video and keyboard loops share one shaped mesh link. Lock IPC only
// for an individual host or viewer request, never for a network round trip.
func (b *echoBench) liveBurst(round int, grant, initial string) {
	t := b.t
	const chars = "春A夏B秋C冬D甲1乙2丙3丁4山E水F云G月界"
	if b.hostCommand("echo-reset") != "ok" || b.note()[5] != initial {
		t.Fatal("dedicated document reset failed")
	}
	clock := func() (start, last, paint, now int64) {
		if _, err := fmt.Sscan(b.viewerCommand("burst-clock"), &start, &last, &paint, &now); err != nil {
			t.Fatal(err)
		}
		return
	}
	type paintedFrame struct {
		img    image.Image
		ms     int64
		stages frameStages
	}
	frames := make(chan paintedFrame, 32)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer close(frames)
		for {
			select {
			case <-stop:
				return
			default:
			}
			img, _ := b.frame()
			if img != nil {
				_, _, paint, _ := clock()
				select {
				case frames <- paintedFrame{img, paint, b.stages}:
				case <-stop:
					return
				}
			}
		}
	}()
	defer func() { close(stop); <-done }()
	next := func() paintedFrame {
		select {
		case f, ok := <-frames:
			if ok {
				return f
			}
		case <-time.After(8 * time.Second):
		}
		t.Fatal("continuous preview stalled")
		return paintedFrame{}
	}
	before := next()
	if b.link.loaded {
		// Redundant copies of a real JPEG fragment keep a bounded video backlog
		// even between captures. They consume mesh bandwidth but are not painted.
		halt, finished := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(finished)
			for {
				select {
				case <-halt:
					return
				default:
				}
				l := &b.link
				l.mu.Lock()
				video := l.video
				ready := len(video) > 0 && (len(l.queue) == 0 || time.Until(l.queue[len(l.queue)-1].end) < 60*time.Millisecond)
				l.mu.Unlock()
				if ready {
					l.enqueue(1, video)
				} else {
					time.Sleep(time.Millisecond)
				}
			}
		}()
		defer func() { close(halt); <-finished }()
		time.Sleep(90 * time.Millisecond)
	}
	if b.viewerCommand("burst "+base64.StdEncoding.EncodeToString([]byte(chars))) != "ok" {
		t.Fatal("burst start failed")
	}
	startLoad := time.Now()
	backlog := func() time.Duration {
		q := b.link.queue
		if len(q) == 0 {
			return 0
		}
		return max(0, time.Until(q[len(q)-1].end))
	}
	b.link.mu.Lock()
	baseBusy := b.link.busy - backlog()
	b.link.mu.Unlock()
	const count = 24
	var lastSent time.Time
	if b.sliding {
		lastSent = b.slideBurst(grant, round*count, count)
	} else {
		for offset := 0; offset < count; offset += 4 {
			var keys []string
			for deadline := time.Now().Add(3 * time.Second); len(keys) < 4; {
				if time.Now().After(deadline) {
					t.Fatal("keyboard producer stalled")
				}
				if k := b.viewerCommand("burst-pop"); k != "empty" {
					keys = append(keys, k)
				} else {
					time.Sleep(4 * time.Millisecond)
				}
			}
			if offset+4 == count {
				lastSent = time.Now()
			}
			b.keyWindow(keys, grant, round*count+offset+1)
		}
	}
	ackAt := time.Now()
	if b.link.loaded {
		b.link.mu.Lock()
		util := float64(b.link.busy-backlog()-baseBusy) / float64(time.Since(startLoad))
		t.Logf("sliding=%t final_send_to_ack_ms=%d", b.sliding, ackAt.Sub(lastSent).Milliseconds())
		t.Logf("priority=%t acks=%d with_video=%d max_queue_ms=%d busy_pct=%.1f", b.link.priority, b.link.acks, b.link.contended, b.link.waitMax.Milliseconds(), 100*util)
		b.link.mu.Unlock()
	}
	start, last, _, now := clock()
	ackMs := now - time.Since(ackAt).Milliseconds() - last
	b.hostMu.Lock()
	note := b.note()
	b.hostMu.Unlock()
	if note[5] != initial+chars {
		t.Fatal("unexpected Notepad text")
	}
	region := b.hostCommand("echo-region")
	overlap := 0
	maxGap := int64(0)
	prevPaint := before.ms
	for until := time.Now().Add(8 * time.Second); time.Now().Before(until); {
		frame := next()
		maxGap = max(maxGap, frame.ms-prevPaint)
		prevPaint = frame.ms
		if frame.ms >= start && frame.ms < last {
			overlap++
		}
		ink := echoInk(before.img, frame.img, region)
		if ink && frame.ms < last {
			t.Fatal("false positive before final key")
		}
		if ink {
			if overlap == 0 {
				t.Fatal("no painted frame during typing")
			}
			s := frame.stages
			boundary := ackAt
			bucket := func(end time.Time) int64 {
				if end.Before(boundary) {
					return 0
				}
				d := end.Sub(boundary)
				boundary = end
				return d.Milliseconds()
			}
			t.Logf("delta=%t full=%d wire=%d after_ack_ms wait/request/capture/transfer/repair/display=%d/%d/%d/%d/%d/%d", b.delta, s.fullBytes, s.wireBytes, bucket(s.request), bucket(s.capture), bucket(s.send), bucket(s.firstPass), bucket(s.received), bucket(s.paint))
			t.Logf("push_mode=%t target_pushed=%t max_paint_gap_ms=%d", b.wakeup != nil, s.pushed, maxGap)
			t.Logf("round=%d typed_ms=%d paints_during_typing=%d last_to_ack_ms=%d last_to_painted_glyph_ms=%d", round+1, last-start, overlap, ackMs, frame.ms-last)
			return
		}
	}
	t.Fatal("final glyph not visible")
}

// A zero tag carries a keyframe. Delta records use a byte count and either
// inline literals (offset zero) or a one-based offset into the previous JPEG.
func packFrame(src, base []byte, id uint32) []byte {
	full := func() []byte { return append([]byte{0}, src...) }
	const block = 32
	if len(base) < block {
		return full()
	}
	index := make(map[[block]byte]int, len(base)/block)
	for i := 0; i+block <= len(base); i += block {
		index[[block]byte(base[i:i+block])] = i
	}
	out := binary.BigEndian.AppendUint32([]byte{1}, id)
	record := func(n, off int) {
		out = binary.AppendUvarint(out, uint64(n))
		out = binary.AppendUvarint(out, uint64(off))
	}
	literal := 0
	for i := 0; i+block <= len(src); {
		pos, ok := index[[block]byte(src[i:i+block])]
		if !ok {
			i++
			continue
		}
		n := block
		for i+n < len(src) && pos+n < len(base) && src[i+n] == base[pos+n] {
			n++
		}
		if i > literal {
			record(i-literal, 0)
			out = append(out, src[literal:i]...)
		}
		record(n, pos+1)
		i += n
		literal = i
	}
	if literal < len(src) {
		record(len(src)-literal, 0)
		out = append(out, src[literal:]...)
	}
	if len(out) >= len(src)+1 {
		return full()
	}
	return out
}
func unpackFrame(payload, base []byte, id uint32) ([]byte, bool) {
	if len(payload) == 0 {
		return nil, false
	}
	if payload[0] == 0 {
		return payload[1:], true
	}
	if len(payload) < 5 || payload[0] != 1 || binary.BigEndian.Uint32(payload[1:]) != id {
		return nil, false
	}
	payload = payload[5:]
	var out []byte
	for len(payload) > 0 {
		n, k := binary.Uvarint(payload)
		if k <= 0 || n == 0 || n > uint64(2_000_000-len(out)) {
			return nil, false
		}
		payload = payload[k:]
		off, k := binary.Uvarint(payload)
		if k <= 0 {
			return nil, false
		}
		payload = payload[k:]
		if off == 0 {
			if n > uint64(len(payload)) {
				return nil, false
			}
			out = append(out, payload[:n]...)
			payload = payload[n:]
		} else {
			if off-1 > uint64(len(base)) || n > uint64(len(base))-(off-1) {
				return nil, false
			}
			out = append(out, base[off-1:off-1+n]...)
		}
	}
	return out, len(out) > 0
}

// An ACK must retain FIFO order with other ACKs and preserve the serialization
// cost of every frame fragment it passes, including the fragment already on wire.
func TestAssistReturnQueueOrder(t *testing.T) {
	start := time.Unix(0, 0)
	for _, priority := range []bool{false, true} {
		l := echoLink{priority: priority}
		first := l.schedule(start, 4*time.Millisecond, false)
		second := l.schedule(start, 4*time.Millisecond, false)
		a := l.schedule(start.Add(time.Millisecond), time.Millisecond, true)
		b := l.schedule(start.Add(2*time.Millisecond), time.Millisecond, true)
		want := []int{4, 8, 9, 10}
		if priority {
			want = []int{4, 10, 5, 6}
		}
		for i, s := range []*returnSlot{first, second, a, b} {
			if got := s.end.Sub(start); got != time.Duration(want[i])*time.Millisecond {
				t.Fatalf("priority=%t slot %d: %s", priority, i, got)
			}
		}
	}
}

// Process ACKs as they arrive. The four-slot receiver and cumulative ACK format
// are unchanged. Retain every unconfirmed character and its original grant.
func (b *echoBench) slideBurst(grant string, base, count int) time.Time {
	type pending struct {
		key      string
		attempts int
		last     time.Time
	}
	type packet struct {
		seq      int
		delivery echoDelivery
	}
	keys := make([]pending, count+1)
	var forward, back []packet
	sent, confirmed := 0, 0
	var finalSent time.Time
	lastObserved := -1
	observe := func() {
		if os.Getenv("CALABI_ASSIST_PUSH") != "1" {
			return
		}
		var length int
		if _, err := fmt.Sscan(b.hostCommand("echo-length"), &length); err != nil {
			b.t.Fatal("no authorized Notepad length")
		}
		if b.wakeup != nil && lastObserved >= 0 && length > lastObserved {
			select {
			case b.wakeup <- struct{}{}:
			default:
			}
		}
		lastObserved = length
	}
	observe()
	push := func(seq int) {
		k := &keys[seq]
		if k.attempts >= 4 {
			b.t.Fatal("sliding window retry budget exhausted")
		}
		k.last = time.Now()
		if seq == count && k.attempts == 0 {
			finalSent = k.last
		}
		loss := seq == 3 && k.attempts == 0
		forward = append(forward, packet{seq, b.link.enqueueWithLoss(0, []byte(k.key), loss)})
		k.attempts++
	}
	// Preserve the deliberate reverse-order fault on the first flight.
	for deadline := time.Now().Add(12 * time.Second); confirmed < count; {
		if time.Now().After(deadline) {
			b.t.Fatal("sliding window stalled")
		}
		for sent < count && sent-confirmed < 4 {
			k := b.viewerCommand("burst-pop")
			if k == "empty" {
				break
			}
			sent++
			f := strings.Fields(k)
			if len(f) != 4 || f[0] != grant || f[3] != fmt.Sprint(base+sent) {
				b.t.Fatal("unexpected sliding input")
			}
			keys[sent].key = k
			if sent == 4 {
				for seq := 1; seq <= 4; seq++ {
					push(seq)
				}
				for i := 0; i < 2; i++ {
					forward[i], forward[3-i] = forward[3-i], forward[i]
				}
			}
			if sent > 4 {
				push(sent)
			}
		}
		for len(forward) > 0 && !time.Now().Before(forward[0].delivery.due) {
			p := forward[0]
			forward = forward[1:]
			if p.delivery.data != nil {
				reply := b.hostCommand(string(p.delivery.data))
				if p.seq <= 4 && confirmed == 0 && keys[p.seq].attempts == 1 && p.seq > 1 && reply != fmt.Sprintf("ack %s %d", grant, base) {
					b.t.Fatal("early cumulative ACK")
				}
				observe()
				loss := p.seq == 7 && keys[7].attempts == 1
				back = append(back, packet{p.seq, b.link.enqueueWithLoss(1, []byte(reply), loss)})
			}
		}
		for len(back) > 0 {
			d := back[0].delivery
			b.link.mu.Lock()
			due := d.slot.end.Add(40 * time.Millisecond)
			b.link.mu.Unlock()
			if time.Now().Before(due) {
				break
			}
			back = back[1:]
			if d.data == nil {
				continue
			}
			var epoch string
			var ack int
			if _, err := fmt.Sscanf(string(d.data), "ack %s %d", &epoch, &ack); err != nil || epoch != grant || ack < base || ack > base+sent {
				b.t.Fatal("invalid sliding acknowledgement")
			}
			confirmed = max(confirmed, ack-base)
		}
		for seq := confirmed + 1; seq <= sent; seq++ {
			k := &keys[seq]
			if k.attempts > 0 && time.Since(k.last) >= 180*time.Millisecond {
				push(seq)
			}
		}
		if confirmed < count {
			time.Sleep(time.Millisecond)
		}
	}
	observe()
	return finalSent
}
