package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/calabi/calabi/apps/client/internal/localweb"
	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// `calabi mesh relaytest` — measure ONE LEG of the relay path.
//
// WHY THIS EXISTS, and why it should have existed sooner.
//
// Every measurement before this one was end to end: a transfer between two mesh
// nodes through a relay. That is three segments (sender->relay, the relay's
// forwarding, relay->receiver) plus two WireGuard datapaths plus two tun
// devices. When the number is bad it says nothing about WHICH part is bad, so
// the only way forward was to change something, redeploy both ends, and measure
// the whole thing again — which took six rounds and reached the wrong conclusion
// twice.
//
// The datapath counters localise LOSS along that chain; that is what they are
// for and they did it, proving every dropped packet was the sender's own. They
// cannot localise CAPACITY. Capacity is not visible in a passive counter — it
// has to be driven.
//
// The relay already has the primitive: it echoes DERPFramePing back as a Pong,
// whatever the payload, up to MaxDERPFrameLen. So one client can drive one leg —
// itself to the relay and back — through the relay's real read and write loops,
// with no second node, no WireGuard, no tun, and none of our own send queue in
// the way. Run it from each end and the segments come apart:
//
//	home ->relay-> home     leg 1 alone
//	mac  ->relay-> mac      leg 3 alone
//	home ->relay-> mac      the full path (iperf3 over the mesh)
//
// A leg that is fast alone and slow in the full path is a relay forwarding
// problem. A leg that is slow alone is that leg's network — and comparing it
// against plain iperf3 to another port on the same host separates "this network
// is slow" from "our code on this network is slow", which is the exact question
// that cost the most time to answer.
type relayTestConfig struct {
	addr    string
	seconds int
	size    int
	rate    float64 // Mbit/s offered; 0 = as fast as the link takes
	oneWay  bool    // drive the send direction alone; no return traffic at all
}

func runMeshRelayTest(args []string) int {
	fs := flag.NewFlagSet("mesh relaytest", flag.ContinueOnError)
	var cfg relayTestConfig
	fs.StringVar(&cfg.addr, "relay", "", "relay address host:port (default: the one the local daemon is using)")
	fs.IntVar(&cfg.seconds, "seconds", 10, "how long to drive the leg")
	fs.IntVar(&cfg.size, "size", 1200, "payload bytes per frame (a mesh packet is about 1200)")
	fs.Float64Var(&cfg.rate, "rate", 0, "offered rate in Mbit/s; 0 = as fast as the link takes")
	fs.BoolVar(&cfg.oneWay, "oneway", false,
		"measure the SEND direction alone: frames go to a destination the relay has no link for, so it "+
			"drops them and nothing comes back. Separates a slow network from a relay that has stalled "+
			"its own read loop writing the reply.")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if cfg.size < 16 || cfg.size > meshproto.MaxDERPFrameLen {
		fmt.Fprintf(os.Stderr, "calabi mesh relaytest: --size must be between 16 and %d\n", meshproto.MaxDERPFrameLen)
		return 2
	}
	// Ask the DAEMON to run it, first and by preference. Its relay link is already
	// authenticated, which a fresh connection from here is not: a relay that
	// requires a coordinator grant rejects the ephemeral key below, and this
	// node's real key cannot be used either because the relay hands a key to the
	// newest connection claiming it — the probe would evict the link it came to
	// measure. The daemon's link is also the one actually carrying traffic, which
	// makes it the more truthful thing to measure.
	if out, err := probeViaDaemon(cfg); err == nil {
		fmt.Print(out)
		return 0
	} else if errors.Is(err, errDaemonCannot) {
		fmt.Fprintf(os.Stderr, "note: %v — dialing it directly instead\n", err)
	} else if !errors.Is(err, errNoDaemon) {
		fmt.Fprintf(os.Stderr, "calabi mesh relaytest: %v\n", err)
		return 1
	}

	// No daemon here. Fall back to driving a connection of our own, which works
	// against a relay that does not require a grant.
	if cfg.addr == "" {
		addr, err := relayAddrFromDaemon()
		if err != nil {
			fmt.Fprintf(os.Stderr, "calabi mesh relaytest: %v\n"+
				"  pass one explicitly:  calabi mesh relaytest --relay host:3340\n", err)
			return 1
		}
		cfg.addr = addr
	}
	res, err := driveRelayLeg(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "calabi mesh relaytest: %v\n", err)
		return 1
	}
	printRelayTest(cfg, res)
	return 0
}

// errNoDaemon means no local daemon answered, so the caller should fall back to
// dialing the relay directly rather than reporting a failure.
var errNoDaemon = errors.New("no local daemon answered")

// errDaemonCannot means the daemon answered but has no link to probe — the
// caller falls back to dialing rather than reporting a failure.
var errDaemonCannot = errors.New("the daemon has no live link to that address")

// addToSecond buckets bytes by the second they were written in.
//
// A single average over the whole run hides the SHAPE, and the shape is what
// separates the two remaining explanations. iperf3 on this same path prints
// 68.8 Mbit/s in its first second and settles at 21 — a burst, then a real rate.
// If our runs are flat and slow from t=0 the cause is structural; if they start
// fast and collapse, something is reacting to the flow. Ten seconds of average
// cannot tell those apart, and reporting only the average is why several rounds
// of this investigation had nothing to go on.
func (r *relayTestResult) addToSecond(elapsed time.Duration, n uint64) {
	i := int(elapsed.Seconds())
	if i < 0 || i > 3600 { // a run cannot be longer than the clamp allows
		return
	}
	for len(r.perSecond) <= i {
		r.perSecond = append(r.perSecond, 0)
	}
	r.perSecond[i] += n
}

// printPerSecond renders the buckets in the same shape iperf3 uses, so the two
// outputs can be read side by side rather than translated.
func printPerSecond(perSecond []uint64) {
	if len(perSecond) < 2 {
		return // one bucket is not a shape
	}
	fmt.Printf("  per second:\n")
	for i, b := range perSecond {
		fmt.Printf("    %2d-%2ds  %7.1f KB   %6.2f Mbit/s\n", i, i+1, float64(b)/1000, float64(b)*8/1e6)
	}
}

// buildProbeFrame makes one probe frame for the direct-dial path.
//
// In one-way mode it is a packet frame addressed to a node key nothing holds:
// against a real relay that means "read it and drop it" (hub.forward), and
// against a PLAIN TCP SINK — nc, socat, anything that reads and discards — it
// means the sink just swallows it. That second case is the point.
//
// It makes the send direction measurable against ANY destination, which is what
// separates "this port is policed" from "this traffic is". iperf3 on a different
// port answers neither: it is a different protocol AND a different port, so a
// fast result there rules out nothing. Pointing THIS at a sink on a port already
// known to be fast changes one variable and only one.
func buildProbeFrame(oneWay bool, payload []byte) ([]byte, error) {
	if !oneWay {
		return meshproto.EncodeDERPFrame(meshproto.DERPFramePing, payload)
	}
	var sink meshproto.NodeKey
	if _, err := rand.Read(sink[:]); err != nil {
		return nil, err
	}
	return meshproto.EncodeDERPFrame(meshproto.DERPFrameSendPacket, meshproto.EncodePacket(sink, payload))
}

// probeViaDaemon asks the running daemon to drive its own relay link.
func probeViaDaemon(cfg relayTestConfig) (string, error) {
	q := url.Values{}
	if cfg.addr != "" {
		q.Set("relay", cfg.addr)
	}
	q.Set("size", strconv.Itoa(cfg.size))
	q.Set("seconds", strconv.Itoa(cfg.seconds))
	q.Set("rate", strconv.FormatFloat(cfg.rate, 'f', -1, 64))
	if cfg.oneWay {
		q.Set("oneway", "1")
	}

	var resp *http.Response
	var err error
	for _, base := range meshConsoleCandidates() {
		req, rerr := http.NewRequest(http.MethodPost, base+"/v1/mesh/relaytest?"+q.Encode(), nil)
		if rerr != nil {
			return "", rerr
		}
		// Per candidate: the token comes from the daemon we are about to ask, not
		// from a file this process happens to be able to read.
		req.Header.Set("X-Local-Token", localTokenFor(base))
		if resp, err = http.DefaultClient.Do(req); err == nil {
			break
		}
	}
	if err != nil || resp == nil {
		return "", errNoDaemon
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		// The daemon is there but has no mesh — fall back rather than fail, so a
		// tunnels-only daemon on the box doesn't block a relay measurement.
		return "", errNoDaemon
	}
	if resp.StatusCode == http.StatusServiceUnavailable {
		// The daemon is willing but cannot: no mesh running, or no live link to the
		// relay that was named. Falling back to a connection of our own is exactly
		// right there — pointing --relay at a plain TCP sink to compare traffic
		// shapes is a case the daemon can never serve, because it only ever probes
		// relays it is already connected to.
		return "", fmt.Errorf("%w: %s", errDaemonCannot, strings.TrimSpace(string(body)))
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the daemon refused the probe (%s): %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var pr localweb.MeshRelayProbe
	if jerr := json.Unmarshal(body, &pr); jerr != nil {
		return "", fmt.Errorf("bad response from the daemon: %w", jerr)
	}
	return formatDaemonProbe(cfg, pr), nil
}

func formatDaemonProbe(cfg relayTestConfig, p localweb.MeshRelayProbe) string {
	var b strings.Builder
	secs := float64(p.ElapsedMs) / 1000
	var offered, delivered, loss float64
	if secs > 0 {
		offered = float64(p.Bytes) * 8 / secs / 1e6
		if p.Sent > 0 {
			delivered = offered * float64(p.Echoed) / float64(p.Sent)
		}
	}
	if p.Sent > 0 {
		loss = float64(p.Sent-p.Echoed) / float64(p.Sent) * 100
	}
	ms := func(us uint64) string { return fmt.Sprintf("%.1fms", float64(us)/1000) }
	if p.OneWay {
		// No echo line and no loss line: there is no return path BY DESIGN, and
		// printing "loss 100%" for it would be a fabricated network fault.
		fmt.Fprintf(&b, "relay leg test  %s   (this device -> relay, SEND DIRECTION ONLY, %d B frames)\n",
			p.Relay, cfg.size)
		fmt.Fprintf(&b, "  accepted  %d frames / %.1f MB    %.1f Mbit/s\n", p.Sent, float64(p.Bytes)/1e6, offered)
		fmt.Fprintf(&b, "  sender    blocked %dms of %dms\n", p.BlockedMs, p.ElapsedMs)
		b.WriteString(oneWayReadingGuide)
		return b.String()
	}
	fmt.Fprintf(&b, "relay leg test  %s   (this device -> relay -> this device, %d B frames, via the daemon's live link)\n",
		p.Relay, cfg.size)
	fmt.Fprintf(&b, "  offered   %d frames / %.1f MB    %.1f Mbit/s\n", p.Sent, float64(p.Bytes)/1e6, offered)
	fmt.Fprintf(&b, "  echoed    %d frames                %.1f Mbit/s    loss %.1f%%\n", p.Echoed, delivered, loss)
	if p.Echoed > 0 {
		fmt.Fprintf(&b, "  rtt       min %s   p50 %s   p90 %s   max %s\n",
			ms(p.RTTMinUs), ms(p.RTTP50Us), ms(p.RTTP90Us), ms(p.RTTMaxUs))
		if p.RTTP50Us > 2_000_000 {
			// The drain window at the end of a run is half a second. On a link whose
			// round trip is measured in SECONDS, most of what was sent is still in
			// flight when the run stops, and the "loss" printed above is mostly that
			// rather than anything the network did.
			b.WriteString("  ⚠ the round trip is seconds long, so most of the loss above is frames still in flight when the run ended\n")
		}
	}
	fmt.Fprintf(&b, "  sender    blocked %dms of %dms\n", p.BlockedMs, p.ElapsedMs)
	b.WriteString(legReadingGuide)
	return b.String()
}

// oneWayReadingGuide explains a measurement with no return path — the mode that
// exists because the echo mode cannot tell a slow network from a relay whose own
// read loop is stalled writing the reply.
const oneWayReadingGuide = `
Send direction only: the frames went to a destination the relay has no link for,
so it read them and dropped them. Nothing came back, by design — there is no
loss figure to report, and none is missing.

  compare with the echo run to the same relay:
    both slow   -> the send direction (this network, or the relay reading)
    echo slower -> the return direction, or the relay stalling its own read loop
                   while it writes the reply
  compare with plain iperf3 to another port on the same host:
    iperf3 fast, this slow -> our code or the relay process, not the network
`

// relayAddrFromDaemon reads the relay the running daemon is actually using, so
// the test measures the leg in question rather than one the operator guessed at.
func relayAddrFromDaemon() (string, error) {
	resp, tried, err := dialMeshConsole("/v1/mesh")
	if err != nil {
		return "", fmt.Errorf("no daemon answered on %s, so the relay address is unknown (%v)", tried, err)
	}
	defer resp.Body.Close()
	var st meshStatusResp
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return "", fmt.Errorf("bad response from the daemon: %w", err)
	}
	if st.Relay == "" {
		return "", fmt.Errorf("the daemon reports no relay")
	}
	return st.Relay, nil
}

type relayTestResult struct {
	sent, sentB   uint64
	echoed        uint64
	echoedB       uint64
	elapsed       time.Duration
	blocked       time.Duration
	rtts          []time.Duration
	authWanted    bool
	linkDiedEarly bool
	// perSecond is bytes written in each elapsed second. See addToSecond.
	perSecond []uint64
}

// driveRelayLeg opens its OWN link to the relay and bounces frames off it.
//
// It announces a RANDOM node key, never this node's. The hub evicts whatever
// link currently holds a key when a new connection claims it, so testing under
// the real key would knock this machine's own relay link offline for the
// duration — a diagnostic that breaks the thing it is diagnosing.
func driveRelayLeg(cfg relayTestConfig) (*relayTestResult, error) {
	conn, err := net.DialTimeout("tcp", cfg.addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", cfg.addr, err)
	}
	defer conn.Close()

	var key meshproto.NodeKey
	if _, err := rand.Read(key[:]); err != nil {
		return nil, fmt.Errorf("ephemeral key: %w", err)
	}
	if err := meshproto.WriteDERPFrame(conn, meshproto.DERPFrameClientInfo, key[:]); err != nil {
		return nil, fmt.Errorf("client info: %w", err)
	}

	var (
		echoed, echoedB atomic.Uint64
		authWanted      atomic.Bool
		mu              sync.Mutex
		rtts            []time.Duration
	)
	done := make(chan struct{})

	// The RTT base. Frames carry NANOSECONDS SINCE start, not a wall-clock
	// instant: reconstructing an instant with time.Unix throws away Go's
	// monotonic reading, and the wall clock's granularity is milliseconds on
	// Windows — which reported a sub-millisecond loopback round trip as exactly
	// zero. Both ends of the subtraction now come from the same monotonic base.
	start := time.Now()

	// Reader. Every Pong carries back the sequence and send offset we put in it,
	// so the RTT needs no clock on the far side and no bookkeeping on this one.
	go func() {
		defer close(done)
		for {
			typ, payload, err := meshproto.ReadDERPFrame(conn)
			if err != nil {
				return
			}
			switch typ {
			case meshproto.DERPFramePong:
				if len(payload) < 16 {
					continue
				}
				sentAt := time.Duration(binary.BigEndian.Uint64(payload[8:16]))
				echoed.Add(1)
				echoedB.Add(uint64(len(payload)))
				mu.Lock()
				rtts = append(rtts, time.Since(start)-sentAt)
				mu.Unlock()
			case meshproto.DERPFrameAuthChallenge:
				// A relay that requires a coordinator grant cannot be driven by an
				// ephemeral key. Say so, rather than reporting a link that just dies.
				authWanted.Store(true)
				return
			}
		}
	}()

	res := &relayTestResult{}
	payload := make([]byte, cfg.size)
	// Frames per second implied by the offered rate; zero means unpaced.
	var gap time.Duration
	if cfg.rate > 0 {
		fps := cfg.rate * 1e6 / 8 / float64(cfg.size)
		gap = time.Duration(float64(time.Second) / fps)
	}

	deadline := start.Add(time.Duration(cfg.seconds) * time.Second)
	next := start
	var seq uint64
	sending := true
	for sending && time.Now().Before(deadline) {
		select {
		case <-done:
			res.linkDiedEarly = true
			sending = false
			continue
		default:
		}
		seq++
		binary.BigEndian.PutUint64(payload[0:8], seq)
		binary.BigEndian.PutUint64(payload[8:16], uint64(time.Since(start)))
		frame, err := buildProbeFrame(cfg.oneWay, payload)
		if err != nil {
			return nil, err
		}
		t0 := time.Now()
		if _, werr := conn.Write(frame); werr != nil {
			res.linkDiedEarly = true
			break
		}
		res.blocked += time.Since(t0)
		res.sent++
		res.sentB += uint64(len(payload))
		res.addToSecond(time.Since(start), uint64(len(payload)))
		if gap > 0 {
			next = next.Add(gap)
			if d := time.Until(next); d > 0 {
				time.Sleep(d)
			}
		}
	}
	res.elapsed = time.Since(start)

	// Let what is still in flight come back before calling it lost. Without this
	// the tail of every run reads as loss that is not there.
	time.Sleep(500 * time.Millisecond)
	_ = conn.Close()
	<-done

	res.echoed = echoed.Load()
	res.echoedB = echoedB.Load()
	res.authWanted = authWanted.Load()
	mu.Lock()
	res.rtts = append([]time.Duration(nil), rtts...)
	mu.Unlock()
	return res, nil
}

func printRelayTest(cfg relayTestConfig, r *relayTestResult) {
	if r.authWanted {
		fmt.Printf("relay %s requires a coordinator grant, and this test dials with an ephemeral\n"+
			"key so it cannot present one. Either run it against a relay with\n"+
			"relay.require_auth off, or measure this leg with plain iperf3 to another port\n"+
			"on the same host.\n", cfg.addr)
		return
	}
	// A run that ended almost immediately has no rate in it. What the number
	// would describe is the socket buffer filling up once — 41 frames in 9 ms
	// printed as "44.2 Mbit/s", which reads exactly like an answer and is not
	// one. The same failure as reporting "loss 100%" for a mode with no replies:
	// a diagnostic that manufactures a plausible figure is worse than one that
	// reports nothing, because the figure gets believed.
	if want := time.Duration(cfg.seconds) * time.Second; r.elapsed < want/2 {
		fmt.Printf("the run ended after %v of the %v asked for — %d frames, %.0f KB.\n",
			r.elapsed.Round(time.Millisecond), want, r.sent, float64(r.sentB)/1000)
		fmt.Printf("No rate is reported: over that little time the only thing measured is the\n" +
			"socket buffer filling once.\n\n")
		if r.linkDiedEarly {
			fmt.Printf("The far end closed the connection. If this address is meant to be a plain\n" +
				"TCP sink, check what is actually listening there — an iperf3 server, for one,\n" +
				"accepts the connection, fails to parse the frames as its own protocol, and\n" +
				"hangs up:\n" +
				"  ss -tlnp | grep <port>\n")
		}
		return
	}
	secs := r.elapsed.Seconds()
	offered := float64(r.sentB) * 8 / secs / 1e6
	delivered := float64(r.echoedB) * 8 / secs / 1e6
	var loss float64
	if r.sent > 0 {
		loss = float64(r.sent-r.echoed) / float64(r.sent) * 100
	}
	if cfg.oneWay {
		// Same rule as the daemon path: nothing was asked to come back, so there is
		// no loss to report and printing one would invent a fault.
		fmt.Printf("send test  %s   (SEND DIRECTION ONLY, %d B frames)\n", cfg.addr, cfg.size)
		fmt.Printf("  accepted  %d frames / %.1f MB    %.1f Mbit/s\n", r.sent, float64(r.sentB)/1e6, offered)
		fmt.Printf("  sender    blocked %v of %v\n",
			r.blocked.Round(time.Millisecond), r.elapsed.Round(time.Millisecond))
		if r.linkDiedEarly {
			fmt.Printf("  ⚠ the connection closed before the run finished\n")
		}
		printPerSecond(r.perSecond)
		fmt.Print(oneWayReadingGuide)
		return
	}
	fmt.Printf("relay leg test  %s   (this device -> relay -> this device, %d B frames)\n", cfg.addr, cfg.size)
	fmt.Printf("  offered   %d frames / %.1f MB    %.1f Mbit/s\n", r.sent, float64(r.sentB)/1e6, offered)
	fmt.Printf("  echoed    %d frames / %.1f MB    %.1f Mbit/s    loss %.1f%%\n",
		r.echoed, float64(r.echoedB)/1e6, delivered, loss)
	if len(r.rtts) > 0 {
		sort.Slice(r.rtts, func(i, j int) bool { return r.rtts[i] < r.rtts[j] })
		// Nearest-rank, rounding up — same convention as derp.ProbeResult.Quantile,
		// and for the same reason: truncating hides exactly the tail a p90 exists
		// to show.
		at := func(q float64) time.Duration {
			idx := int(math.Ceil(q*float64(len(r.rtts)))) - 1
			if idx < 0 {
				idx = 0
			}
			return r.rtts[idx]
		}
		fmt.Printf("  rtt       min %v   p50 %v   p90 %v   max %v\n",
			r.rtts[0].Round(time.Millisecond), at(0.5).Round(time.Millisecond),
			at(0.9).Round(time.Millisecond), r.rtts[len(r.rtts)-1].Round(time.Millisecond))
	}
	fmt.Printf("  writer    blocked %v of %v\n",
		r.blocked.Round(time.Millisecond), r.elapsed.Round(time.Millisecond))
	if r.linkDiedEarly {
		fmt.Printf("  ⚠ the link closed before the run finished; the rates above cover less time than asked for\n")
	}
	fmt.Print(legReadingGuide)
}

// legReadingGuide is printed by BOTH output paths. The whole point of measuring
// one segment is that the number means something specific, and that meaning is
// what a reader needs next to it — kept in one place so the two paths cannot
// come to say different things about the same measurement.
const legReadingGuide = `
This is ONE leg: driven to the relay and back through its own read and write
loops, with no second node, no WireGuard, no tun and no send queue in the way.

  slow here, and plain iperf3 to another port on this host is also slow
      -> the network on this leg is the limit
  slow here, but plain iperf3 to another port on this host is fast
      -> our code or the relay process is the limit, not the network
  fast here, but a mesh transfer through this relay is slow
      -> the far leg or the relay's forwarding, not this one
`
