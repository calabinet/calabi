package main

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/localweb"
	"github.com/calabinet/calabi/apps/client/internal/mesh/derp"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// A query string must not be able to pin the node's relay link to a measurement
// for an hour, or to ask for a frame the protocol cannot carry. The clamp lives
// in ONE place for both daemon kinds: two copies of a bound is two chances for
// them to disagree, which is how the datapath shapes drifted before.
func TestProbeArgsAreClamped(t *testing.T) {
	cases := []struct {
		name        string
		size        int
		rate        float64
		seconds     int
		wantSize    int
		wantRate    float64
		wantSeconds int
	}{
		{"sane values pass through", 1200, 10, 15, 1200, 10, 15},
		{"absurd duration", 1200, 10, 86400, 1200, 10, 60},
		{"zero duration", 1200, 10, 0, 1200, 10, 1},
		{"oversize frame", 1 << 20, 10, 10, 60000, 10, 10},
		{"undersize frame leaves room for the header", 1, 10, 10, 16, 10, 10},
		{"negative rate means unpaced", 1200, -5, 10, 1200, 0, 10},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			size, rate, seconds := clampProbeArgs(c.size, c.rate, c.seconds)
			if size != c.wantSize || rate != c.wantRate || seconds != c.wantSeconds {
				t.Errorf("clamp(%d, %v, %d) = (%d, %v, %d), want (%d, %v, %d)",
					c.size, c.rate, c.seconds, size, rate, seconds, c.wantSize, c.wantRate, c.wantSeconds)
			}
		})
	}
}

// A probe with no datapath must say so rather than report zeros. Zeros would
// read as "the leg carried nothing", which is a measurement, and this is the
// absence of one.
func TestProbeWithoutADatapathReportsAnError(t *testing.T) {
	if _, err := probeRelayLeg(t.Context(), nil, "", 1200, 10, 5, false); err == nil {
		t.Error("probing with no datapath returned no error; a caller would read the zero result as a measurement")
	}
}

// The wire shape must carry what was measured. A field that silently stays zero
// here is the failure that lost rtt_micros in 1.7.1: not a missing number, a
// wrong one.
func TestShapeProbeCarriesEveryMeasurement(t *testing.T) {
	res := &derp.ProbeResult{
		Sent:    100,
		Echoed:  90,
		Bytes:   120000,
		Elapsed: 10 * time.Second,
		Blocked: 250 * time.Millisecond,
		RTTs: []time.Duration{
			10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond,
			40 * time.Millisecond, 900 * time.Millisecond,
		},
	}
	got := shapeProbe("relay.example:3340", res)

	if got.Relay != "relay.example:3340" || got.Sent != 100 || got.Echoed != 90 || got.Bytes != 120000 {
		t.Errorf("counters came across as %+v", got)
	}
	if got.ElapsedMs != 10000 {
		t.Errorf("elapsed_ms = %d, want 10000", got.ElapsedMs)
	}
	if got.BlockedMs != 250 {
		t.Errorf("blocked_ms = %d, want 250", got.BlockedMs)
	}
	// Microseconds, not milliseconds: a healthy relay leg is a low double-digit
	// number of milliseconds, and rounding to whole ones throws away most of what
	// separates a good leg from a degrading one.
	if got.RTTMinUs != 10000 {
		t.Errorf("rtt_min_us = %d, want 10000", got.RTTMinUs)
	}
	if got.RTTMaxUs != 900000 {
		t.Errorf("rtt_max_us = %d, want 900000", got.RTTMaxUs)
	}
	// The tail is the point of reporting a p90 at all: the mean of this sample
	// hides the 900 ms outlier that a user would actually feel.
	if got.RTTP50Us != 30000 {
		t.Errorf("rtt_p50_us = %d, want 30000", got.RTTP50Us)
	}
	if got.RTTP90Us != 900000 {
		t.Errorf("rtt_p90_us = %d, want 900000", got.RTTP90Us)
	}
}

// An empty result must not invent RTTs. Reporting 0 ms for a leg that answered
// nothing would read as a perfect link.
func TestShapeProbeLeavesRTTsUnsetWhenNothingCameBack(t *testing.T) {
	got := shapeProbe("relay.example:3340", &derp.ProbeResult{Sent: 50, Elapsed: time.Second})
	if got.RTTMinUs != 0 || got.RTTP50Us != 0 || got.RTTP90Us != 0 || got.RTTMaxUs != 0 {
		t.Errorf("RTTs reported for a leg that echoed nothing: %+v", got)
	}
	if got.Echoed != 0 {
		t.Errorf("echoed = %d, want 0", got.Echoed)
	}
}

// The one-way mode has no return path BY DESIGN, and the output must not turn
// that into a loss figure. "loss 100%" on a leg that was never asked to reply is
// a fabricated network fault, and it would be a convincing one.
func TestOneWayOutputReportsNoLoss(t *testing.T) {
	out := formatDaemonProbe(relayTestConfig{size: 1200, oneWay: true}, localweb.MeshRelayProbe{
		Relay: "relay.example:3340", Sent: 5000, Echoed: 0, OneWay: true,
		Bytes: 6000000, ElapsedMs: 10000, BlockedMs: 9000,
	})
	// Only the MEASUREMENT lines are checked, not the prose that follows: the
	// guide has to be free to say "there is no loss figure to report", and an
	// assertion over the whole output would forbid explaining the very thing it
	// is guarding. The reported numbers end at the blank line before the guide.
	numbers, _, _ := strings.Cut(out, "\n\n")
	if strings.Contains(numbers, "loss") {
		t.Errorf("the one-way output reports loss, which does not exist in this mode:\n%s", numbers)
	}
	if strings.Contains(numbers, "echoed") {
		t.Errorf("the one-way output reports echoes, which are not asked for in this mode:\n%s", numbers)
	}
	if !strings.Contains(out, "SEND DIRECTION ONLY") {
		t.Errorf("the one-way output does not say which direction it measured:\n%s", out)
	}
	if !strings.Contains(out, "4.8 Mbit/s") {
		t.Errorf("6 MB in 10 s should read as 4.8 Mbit/s accepted:\n%s", out)
	}
}

// And the echo mode must warn when its own loss figure is untrustworthy. The run
// drains for half a second at the end; on a link whose round trip is measured in
// seconds, most of what was sent is still in flight when it stops, and reporting
// that as loss sent a whole round of investigation at the wrong thing.
func TestEchoOutputFlagsTruncatedLossOnASecondsLongLink(t *testing.T) {
	slow := formatDaemonProbe(relayTestConfig{size: 1200}, localweb.MeshRelayProbe{
		Relay: "relay.example:3340", Sent: 7042, Echoed: 2926,
		Bytes: 8500000, ElapsedMs: 10597, BlockedMs: 6456,
		RTTMinUs: 347700, RTTP50Us: 4410500, RTTP90Us: 7477400, RTTMaxUs: 8252800,
	})
	if !strings.Contains(slow, "still in flight") {
		t.Errorf("a 4.4 s round trip with 58%% apparent loss is not flagged as truncated:\n%s", slow)
	}
	fast := formatDaemonProbe(relayTestConfig{size: 1200}, localweb.MeshRelayProbe{
		Relay: "relay.example:3340", Sent: 3360, Echoed: 3360,
		Bytes: 4000000, ElapsedMs: 10093, BlockedMs: 9596,
		RTTMinUs: 4300, RTTP50Us: 129800, RTTP90Us: 180400, RTTMaxUs: 214800,
	})
	if strings.Contains(fast, "still in flight") {
		t.Errorf("a 130 ms round trip should not be flagged as truncated:\n%s", fast)
	}
}

// The direct-dial path must honour --oneway too. It used to REFUSE the flag
// there, which was safe but blocked the measurement that matters most now:
// pointing our own traffic shape at a plain TCP sink on a port already known to
// be fast. That changes exactly one variable — the traffic, not the port — which
// is what iperf3 on another port can never do, because it changes both.
func TestOneWayFrameIsAPacketToNobody(t *testing.T) {
	payload := make([]byte, 64)
	frame, err := buildProbeFrame(true, payload)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if got := meshproto.DERPFrameType(frame[0]); got != meshproto.DERPFrameSendPacket {
		t.Errorf("frame type %v, want SendPacket (a Ping would be echoed, which is the whole thing this avoids)", got)
	}
	// Two different frames must not carry the same destination: a fixed key could
	// one day belong to a real node, and the probe would then be delivered to it.
	a, _ := buildProbeFrame(true, payload)
	b, _ := buildProbeFrame(true, payload)
	if string(a[5:5+meshproto.KeyLen]) == string(b[5:5+meshproto.KeyLen]) {
		t.Error("the sink key is fixed; it should be random so it cannot collide with a real node")
	}
}

func TestEchoFrameIsStillAPing(t *testing.T) {
	frame, err := buildProbeFrame(false, make([]byte, 64))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if got := meshproto.DERPFrameType(frame[0]); got != meshproto.DERPFramePing {
		t.Errorf("frame type %v, want Ping", got)
	}
}

// A run that died in the first moments has no rate in it, and printing one is
// how a diagnostic lies convincingly. The case that produced this: an iperf3
// server was still listening on the port meant to hold a plain TCP sink, so it
// accepted, failed to parse our frames, and hung up after 41 frames in 9 ms —
// which the tool reported as "44.2 Mbit/s".
func TestTruncatedRunReportsNoRate(t *testing.T) {
	out := captureStdout(t, func() {
		printRelayTest(relayTestConfig{seconds: 10, size: 1200, oneWay: true}, &relayTestResult{
			sent: 41, sentB: 49200, elapsed: 9 * time.Millisecond,
			blocked: time.Millisecond, linkDiedEarly: true,
		})
	})
	if strings.Contains(out, "Mbit/s") {
		t.Errorf("a 9 ms run reported a rate:\n%s", out)
	}
	if !strings.Contains(out, "socket buffer filling") {
		t.Errorf("the output does not say why no rate is reported:\n%s", out)
	}
	if !strings.Contains(out, "ss -tlnp") {
		t.Errorf("a far end that hung up should point at what to check:\n%s", out)
	}
}

// And a run that DID complete still reports normally — the guard must not
// swallow real measurements.
func TestCompleteRunStillReportsARate(t *testing.T) {
	out := captureStdout(t, func() {
		printRelayTest(relayTestConfig{seconds: 10, size: 1200, oneWay: true}, &relayTestResult{
			sent: 3430, sentB: 4116000, elapsed: 10 * time.Second, blocked: 9724 * time.Millisecond,
		})
	})
	if !strings.Contains(out, "Mbit/s") {
		t.Errorf("a full-length run reported no rate:\n%s", out)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	b, _ := io.ReadAll(r)
	return string(b)
}

// The per-second buckets are the instrument that separates "slow from t=0" from
// "fast then collapsed" — the two remaining explanations for a leg that reports
// 3 Mbit/s on average. An average over ten seconds cannot tell them apart, and
// reporting only the average is why several rounds of this had nothing to go on.
func TestPerSecondBucketsFollowTheClock(t *testing.T) {
	var r relayTestResult
	r.addToSecond(100*time.Millisecond, 1000)
	r.addToSecond(900*time.Millisecond, 500)
	r.addToSecond(2500*time.Millisecond, 7000) // second 1 is skipped: nothing was written
	if len(r.perSecond) != 3 {
		t.Fatalf("buckets = %v, want three (0, 1, 2)", r.perSecond)
	}
	if r.perSecond[0] != 1500 {
		t.Errorf("second 0 = %d, want 1500", r.perSecond[0])
	}
	if r.perSecond[1] != 0 {
		t.Errorf("second 1 = %d, want 0 — a second with no writes must stay visible as zero, "+
			"because a stall is exactly what this is looking for", r.perSecond[1])
	}
	if r.perSecond[2] != 7000 {
		t.Errorf("second 2 = %d, want 7000", r.perSecond[2])
	}
}

// A run so short it produced one bucket has no shape, and printing a one-row
// "per second" table implies a trend that is not there.
func TestPerSecondPrintsNothingWithoutAShape(t *testing.T) {
	if out := captureStdout(t, func() { printPerSecond([]uint64{1234}) }); out != "" {
		t.Errorf("a single bucket printed a table:\n%s", out)
	}
	if out := captureStdout(t, func() { printPerSecond([]uint64{1234, 5678}) }); out == "" {
		t.Error("two buckets printed nothing")
	}
}
