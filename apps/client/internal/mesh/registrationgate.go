package mesh

import "context"

// A user declaration edit may have its own request context. Session shutdown
// must not wait for that request to finish before it can leave recovery.
func (c *Controller) lockRegistration(ctx context.Context) (func(), error) {
	c.registrationOnce.Do(func() { c.registrationGate = make(chan struct{}, 1) })
	select {
	case c.registrationGate <- struct{}{}:
		return func() { <-c.registrationGate }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
