// Package bus is the edge's event-bus contract: the narrow surface the edge
// consumes, declared here rather than imported from pkg/eventbus.
//
// WHY: pkg/eventbus carries the platform's
// NATS subject names, payload shapes and the real NATS client. None of that may
// reach the public tree, and importing it for four type declarations would have
// been the last thing keeping the edge tied to a closed package after the
// control-plane contract was already cut.
//
// The edge does not dial NATS any more either. Since F3 step 2b every edge
// reaches the control plane through bff-edge, and its bus is the bff-edge-backed
// implementation in internal/platform/bffedgeclient — Subscribe becomes a
// SubscribeXxx stream, Publish becomes a ReportUsage call. So this package
// declares what the edge USES and nothing implements it here.
//
// The method set matches eventbus.Bus exactly, so the platform implementation
// satisfies both without an adapter.
package bus

// Msg is the wire payload plus the subject it landed on.
type Msg struct {
	Subject string
	Data    []byte
}

// Subscription is what Subscribe returns; drain it to stop receiving.
type Subscription interface {
	Drain() error
}

// Bus is the publish/subscribe surface the edge consumes.
type Bus interface {
	// Publish fires a fire-and-forget message.
	Publish(subject string, payload []byte) error
	// Subscribe delivers every matching message to this subscriber. The
	// handler runs on the transport's own goroutine pool — keep it cheap and
	// non-blocking. Drain the returned Subscription when done.
	Subscribe(subject string, handler func(msg *Msg)) (Subscription, error)
	// QueueSubscribe joins a queue group: exactly one member receives each
	// matching message. Behaves like Subscribe when the group has one member.
	QueueSubscribe(subject, queue string, handler func(msg *Msg)) (Subscription, error)
	// Close releases the underlying transport.
	Close() error
}
