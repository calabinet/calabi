// bus.go — eventbus.Bus implementation backed by bff_edge streams.
//
// The cluster NATS broker isn't reachable from cross-region edges, so
// this Bus translates the edge's existing eventbus calls into bff-edge
// RPCs:
//
//	Subscribe("calabi.cert.upsert.>")    → SubscribeCertEvents stream, Kind="upsert"
//	Subscribe("calabi.cert.delete.>")    → SubscribeCertEvents stream, Kind="delete"
//	Subscribe("calabi.online_cap.evict.<id>") → SubscribeSessionEvictEvents stream
//	Subscribe("calabi.usage.deny.>")     → SubscribeUsageEvents stream, Kind="deny"
//	Subscribe("calabi.usage.allow.>")    → SubscribeUsageEvents stream, Kind="allow"
//	Publish("calabi.usage.report", body) → ReportUsage unary (one report at a time)
//
// Any other subject is silently dropped (Publish) or returns a no-op
// subscription (Subscribe) with a warning log. This keeps backward
// compatibility with edge components that publish/subscribe optional
// subjects we haven't taught the bridge about yet.
//
// One stream per Subscribe call. The edge typically calls Subscribe
// 5–7 times at boot (certclient, evict, deny+allow), so the steady
// state is a handful of concurrent server-streams over the shared
// mTLS conn — far fewer than the per-RPC churn elsewhere.

package bffedgeclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	bffedge "github.com/calabi/calabi/pkg/edge-proto/edgepb"
	"github.com/calabi/calabi/pkg/certevents"
	eventbus "github.com/calabi/calabi/apps/calabi-edge/internal/bus"
)

// Bus implements eventbus.Bus on top of bff_edge.BFFEdgeClient. Safe
// for concurrent use across goroutines.
type Bus struct {
	logger *slog.Logger
	client bffedge.BFFEdgeClient

	// ctx is the long-lived context derived from the caller's ctx +
	// our own cancel. All Subscribe streams hang off it so Close()
	// reliably reaps every goroutine.
	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex
	subs      []*subscription
	closed    bool
}

// NewBus wraps client with the eventbus.Bus surface. The parent ctx
// should be the edge's main lifecycle ctx — cancelling it triggers
// Close() semantics on every subscription.
func NewBus(parent context.Context, logger *slog.Logger, client bffedge.BFFEdgeClient) *Bus {
	ctx, cancel := context.WithCancel(parent)
	return &Bus{
		logger: logger.With("component", "bffedgeclient.bus"),
		client: client,
		ctx:    ctx,
		cancel: cancel,
	}
}

// Compile-time guarantee: *Bus satisfies eventbus.Bus.
var _ eventbus.Bus = (*Bus)(nil)

// Publish routes to the matching bff_edge RPC. Unknown subjects log a
// warning and return nil — callers don't fail because of an unmapped
// subject.
func (b *Bus) Publish(subject string, payload []byte) error {
	if subject == "calabi.usage.report" {
		return b.publishUsageReport(payload)
	}
	if subject == "calabi.usage.relay" {
		return b.publishRelayUsageReport(payload)
	}
	b.logger.Warn("bff-edge Publish: unmapped subject; dropping",
		"subject", subject, "bytes", len(payload))
	return nil
}

// publishUsageReport parses the JSON Report shape the edge's usage
// reporter emits and forwards as one bff_edge.UsageReport entry.
// Errors that aren't transport-level get demoted to "warn + drop"
// so a single malformed report doesn't poison the tick.
func (b *Bus) publishUsageReport(payload []byte) error {
	// Mirror apps/calabi-edge/internal/usage.Report — fields named to
	// match the legacy wire format used on cluster NATS.
	var rep struct {
		EdgeNodeID string `json:"edge_node_id"`
		OrgID      int64  `json:"org_id"`
		TunnelID   int64  `json:"tunnel_id"`
		Timestamp  int64  `json:"ts"`
		BytesIn    uint64 `json:"bytes_in"`
		BytesOut   uint64 `json:"bytes_out"`
	}
	if err := json.Unmarshal(payload, &rep); err != nil {
		b.logger.Warn("bff-edge Publish: unmarshal usage report failed",
			"err", err)
		return nil
	}
	ctx, cancel := context.WithTimeout(b.ctx, 5*time.Second)
	defer cancel()
	req := &bffedge.ReportUsageRequest{
		Reports: []*bffedge.UsageReport{
			{
				OrgId:         rep.OrgID,
				TunnelId:      rep.TunnelID,
				BytesIn:       int64safeUint64(rep.BytesIn),
				BytesOut:      int64safeUint64(rep.BytesOut),
				WindowCloseAt: timestamppb.New(time.Unix(rep.Timestamp, 0)),
			},
		},
	}
	if _, err := b.client.ReportUsage(ctx, req); err != nil {
		return fmt.Errorf("bff-edge ReportUsage: %w", err)
	}
	return nil
}

// publishRelayUsageReport parses the JSON relay-usage shape a merged edge/relay
// node emits (edge/derp merge) and forwards it as one bff_edge.RelayUsageReport.
// Same warn+drop discipline as publishUsageReport.
func (b *Bus) publishRelayUsageReport(payload []byte) error {
	var rep struct {
		OrgID     int64  `json:"org_id"`
		Region    string `json:"region"`
		Timestamp int64  `json:"ts"`
		BytesIn   int64  `json:"bytes_in"`
		BytesOut  int64  `json:"bytes_out"`
	}
	if err := json.Unmarshal(payload, &rep); err != nil {
		b.logger.Warn("bff-edge Publish: unmarshal relay usage report failed", "err", err)
		return nil
	}
	ctx, cancel := context.WithTimeout(b.ctx, 5*time.Second)
	defer cancel()
	req := &bffedge.ReportRelayUsageRequest{
		Reports: []*bffedge.RelayUsageReport{
			{
				OrgId:         rep.OrgID,
				Region:        rep.Region,
				BytesIn:       rep.BytesIn,
				BytesOut:      rep.BytesOut,
				WindowCloseAt: timestamppb.New(time.Unix(rep.Timestamp, 0)),
			},
		},
	}
	if _, err := b.client.ReportRelayUsage(ctx, req); err != nil {
		return fmt.Errorf("bff-edge ReportRelayUsage: %w", err)
	}
	return nil
}

// Subscribe routes to the matching SubscribeXxx stream. Returns a
// no-op Subscription with a warning when the subject pattern isn't
// recognized.
func (b *Bus) Subscribe(subject string, handler func(msg *eventbus.Msg)) (eventbus.Subscription, error) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil, errors.New("bff-edge bus closed")
	}
	b.mu.Unlock()

	switch {
	case subject == "calabi.cert.upsert.>":
		return b.subscribeCertEvents("upsert", handler)
	case subject == "calabi.cert.delete.>":
		return b.subscribeCertEvents("delete", handler)
	case subject == certevents.SubjectACMEChallengePresent:
		// ACME http-01 challenge tokens (self-service custom-domain cert
		// issuance). Carried over the same SubscribeCertEvents stream, keyed
		// by Kind. Without these two cases a BYOI edge can't answer the Let's
		// Encrypt probe for its own domain → the validation 404s.
		return b.subscribeCertEvents("acme_present", handler)
	case subject == certevents.SubjectACMEChallengeCleanup:
		return b.subscribeCertEvents("acme_cleanup", handler)
	case strings.HasPrefix(subject, "calabi.online_cap.evict."):
		return b.subscribeEvictEvents(subject, handler)
	case subject == "calabi.usage.deny.>":
		return b.subscribeUsageEvents("deny", handler)
	case subject == "calabi.usage.allow.>":
		return b.subscribeUsageEvents("allow", handler)
	default:
		b.logger.Warn("bff-edge Subscribe: unmapped subject; noop",
			"subject", subject)
		return noopSubscription{}, nil
	}
}

// QueueSubscribe collapses to Subscribe — bff-edge has no queue-group
// concept and the cross-region edge always wants every message anyway.
func (b *Bus) QueueSubscribe(subject, _ string, handler func(msg *eventbus.Msg)) (eventbus.Subscription, error) {
	return b.Subscribe(subject, handler)
}

// Close cancels all subscriptions. Bus methods return errors after
// Close; calling Close twice is fine.
func (b *Bus) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	subs := b.subs
	b.subs = nil
	b.mu.Unlock()
	b.cancel()
	for _, s := range subs {
		_ = s.Drain()
	}
	return nil
}

// ===================== Stream subscription glue =====================

type subscription struct {
	logger  *slog.Logger
	cancel  context.CancelFunc
	doneCh  chan struct{}
}

func (s *subscription) Drain() error {
	s.cancel()
	// Best-effort wait; if the goroutine is wedged in stream.Recv()
	// the cancel above will trip it on the next NATS tick.
	select {
	case <-s.doneCh:
	case <-time.After(2 * time.Second):
		s.logger.Warn("subscription drain timed out")
	}
	return nil
}

// addSub tracks a subscription for Close-time cleanup.
func (b *Bus) addSub(s *subscription) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subs = append(b.subs, s)
}

// subscribeCertEvents opens a SubscribeCertEvents stream and dispatches
// matching kind events to handler. The original NATS subject is
// preserved in the Msg.Subject so the existing edge code's
// certevents.ParseSubject calls keep working.
// reconnectingStream pumps `recv(stream)` until it errors, then RE-OPENS via
// `open` with capped exponential backoff, until the subscription ctx is
// cancelled (Drain/Close). `first` is the already-opened stream so the caller
// keeps its fail-fast "return error if the very FIRST open fails" contract.
// recv pulls + dispatches one event, returning the stream error when it dies.
//
// Why this exists: the edge's cert / usage / evict events all ride bff-edge
// server-streams. Without reconnect, a single bff-edge restart — a routine
// control-plane redeploy — permanently and SILENTLY kills delivery until the
// edge is restarted. The sharpest symptom: ACME http-01 challenge tokens stop
// arriving, so self-service cert issuance fails its validation with a 404.
func reconnectingStream[S any](
	ctx context.Context,
	doneCh chan struct{},
	logger *slog.Logger,
	first S,
	open func(context.Context) (S, error),
	recv func(S) error,
) {
	defer close(doneCh)
	const base, max = 500 * time.Millisecond, 30 * time.Second
	backoff := base
	stream := first
	for {
		// Pump the current stream until it dies.
		for {
			if err := recv(stream); err != nil {
				if ctx.Err() != nil {
					return
				}
				logger.Info("stream dropped; will reconnect", "err", err)
				break
			}
			backoff = base // healthy traffic resets the backoff
		}
		// Re-open with backoff until it succeeds or we're cancelled.
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff *= 2; backoff > max {
				backoff = max
			}
			s, err := open(ctx)
			if err == nil {
				stream = s
				backoff = base
				logger.Info("stream reconnected")
				break
			}
			if ctx.Err() != nil {
				return
			}
			logger.Info("resubscribe failed; will retry", "err", err)
		}
	}
}

func (b *Bus) subscribeCertEvents(wantKind string, handler func(*eventbus.Msg)) (eventbus.Subscription, error) {
	ctx, cancel := context.WithCancel(b.ctx)
	doneCh := make(chan struct{})
	logger := b.logger.With("stream", "SubscribeCertEvents", "kind", wantKind)

	open := func(c context.Context) (bffedge.BFFEdge_SubscribeCertEventsClient, error) {
		return b.client.SubscribeCertEvents(c, &bffedge.SubscribeCertEventsRequest{})
	}
	stream, err := open(ctx)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("open SubscribeCertEvents: %w", err)
	}
	recv := func(s bffedge.BFFEdge_SubscribeCertEventsClient) error {
		ev, err := s.Recv()
		if err != nil {
			return err
		}
		if ev.GetKind() == wantKind {
			handler(&eventbus.Msg{Subject: ev.GetSubject(), Data: ev.GetBodyJson()})
		}
		return nil
	}

	sub := &subscription{logger: logger, cancel: cancel, doneCh: doneCh}
	b.addSub(sub)
	go reconnectingStream(ctx, doneCh, logger, stream, open, recv)
	return sub, nil
}

// subscribeEvictEvents opens a SubscribeSessionEvictEvents stream.
// The subject filtering is implicit (bff-edge sends only events for
// this edge), so we ignore the caller's subject argument apart from
// stamping it on the delivered Msg for downstream parity.
func (b *Bus) subscribeEvictEvents(callerSubject string, handler func(*eventbus.Msg)) (eventbus.Subscription, error) {
	ctx, cancel := context.WithCancel(b.ctx)
	doneCh := make(chan struct{})
	logger := b.logger.With("stream", "SubscribeSessionEvictEvents",
		"caller_subject", callerSubject)

	open := func(c context.Context) (bffedge.BFFEdge_SubscribeSessionEvictEventsClient, error) {
		return b.client.SubscribeSessionEvictEvents(c, &bffedge.SubscribeSessionEvictEventsRequest{})
	}
	stream, err := open(ctx)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("open SubscribeSessionEvictEvents: %w", err)
	}
	recv := func(s bffedge.BFFEdge_SubscribeSessionEvictEventsClient) error {
		ev, err := s.Recv()
		if err != nil {
			return err
		}
		subject := ev.GetSubject()
		if subject == "" {
			subject = callerSubject
		}
		handler(&eventbus.Msg{Subject: subject, Data: ev.GetBodyJson()})
		return nil
	}

	sub := &subscription{logger: logger, cancel: cancel, doneCh: doneCh}
	b.addSub(sub)
	go reconnectingStream(ctx, doneCh, logger, stream, open, recv)
	return sub, nil
}

// subscribeUsageEvents opens a SubscribeUsageEvents stream and filters
// by kind. One physical stream per Subscribe call; the alternative —
// multiplexing — is more code for a saving of one stream.
func (b *Bus) subscribeUsageEvents(wantKind string, handler func(*eventbus.Msg)) (eventbus.Subscription, error) {
	ctx, cancel := context.WithCancel(b.ctx)
	doneCh := make(chan struct{})
	logger := b.logger.With("stream", "SubscribeUsageEvents", "kind", wantKind)

	open := func(c context.Context) (bffedge.BFFEdge_SubscribeUsageEventsClient, error) {
		return b.client.SubscribeUsageEvents(c, &bffedge.SubscribeUsageEventsRequest{})
	}
	stream, err := open(ctx)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("open SubscribeUsageEvents: %w", err)
	}
	recv := func(s bffedge.BFFEdge_SubscribeUsageEventsClient) error {
		ev, err := s.Recv()
		if err != nil {
			return err
		}
		if ev.GetKind() == wantKind {
			handler(&eventbus.Msg{Subject: ev.GetSubject(), Data: ev.GetBodyJson()})
		}
		return nil
	}

	sub := &subscription{logger: logger, cancel: cancel, doneCh: doneCh}
	b.addSub(sub)
	go reconnectingStream(ctx, doneCh, logger, stream, open, recv)
	return sub, nil
}

// noopSubscription is what Subscribe returns for unmapped subjects.
type noopSubscription struct{}

func (noopSubscription) Drain() error { return nil }

// int64safeUint64 clamps overflow when reusing the legacy uint64 byte
// counters into the proto's int64 field.
func int64safeUint64(v uint64) int64 {
	const max = int64(^uint64(0) >> 1)
	if v > uint64(max) {
		return max
	}
	return int64(v)
}
