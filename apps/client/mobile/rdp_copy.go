package mobile

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
)

type rdpCopyLease struct {
	key       string
	ctx       context.Context
	cancel    context.CancelFunc
	verified  atomic.Bool
	mu        sync.Mutex
	agent     *filetransfer.Agent
	id        string
	receiving atomic.Bool
}

func newRDPCopyLease() (*rdpCopyLease, error) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &rdpCopyLease{key: hex.EncodeToString(key[:]), ctx: ctx, cancel: cancel}, nil
}

func (l *rdpCopyLease) close() {
	if l == nil {
		return
	}
	l.cancel()
	go func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.agent != nil && l.id != "" {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			l.agent.CopyClose(ctx, l.id)
			l.id = ""
		}
	}()
}

func (c *Core) rdpCopyTicket(token string) (rdpTicket, error) {
	c.rdpMu.Lock()
	ticket := c.rdpTickets[token]
	c.rdpMu.Unlock()
	if ticket.copy == nil || ticket.copy.ctx.Err() != nil || !ticket.copy.verified.Load() || time.Now().After(ticket.expires) {
		return rdpTicket{}, errors.New("RDP file copy is unavailable")
	}
	current, err := c.resolveRDP(ticket.key)
	if err != nil || current.engine != ticket.engine || current.context != ticket.context ||
		current.local != ticket.local || current.peer != ticket.peer || current.pin != ticket.pin || !current.permitsPort(ticket.port) {
		return rdpTicket{}, errors.New("remote desktop authorization changed")
	}
	return ticket, nil
}

// RdpCopyPoll establishes or renews the file lease and returns the current peer offer.
func (c *Core) RdpCopyPoll(token string) (string, error) {
	ticket, err := c.rdpCopyTicket(token)
	if err != nil {
		return "", err
	}
	l := ticket.copy
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.id == "" {
		c.fileMu.Lock()
		f, err := c.ensureFiles()
		live := err == nil && c.filesLive(f)
		c.fileMu.Unlock()
		if !live {
			return "", errors.New("file transport is unavailable")
		}
		id, err := f.w.Agent.CopyStart(l.ctx, netip.MustParseAddr(ticket.peer), uint16(ticket.port), l.key)
		if err != nil {
			return "", err
		}
		l.agent, l.id = f.w.Agent, id
	} else if err := l.agent.CopyRenew(l.ctx, l.id); err != nil {
		l.agent, l.id = nil, ""
		return "", err
	}
	snapshot := l.agent.CopySnapshot()
	if snapshot.Session != l.id {
		l.agent, l.id = nil, ""
		return "", filetransfer.ErrCopySessionEnded
	}
	b, err := json.Marshal(struct {
		Offer string                  `json:"offer"`
		Files []filetransfer.CopyFile `json:"files"`
	}{snapshot.Offer, snapshot.Files})
	return string(b), err
}

func (c *Core) rdpCopyAgent(token string) (*rdpCopyLease, *filetransfer.Agent, string, error) {
	ticket, err := c.rdpCopyTicket(token)
	if err != nil {
		return nil, nil, "", err
	}
	l := ticket.copy
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.id == "" || l.agent == nil {
		return nil, nil, "", filetransfer.ErrCopySessionEnded
	}
	return l, l.agent, l.id, nil
}

// RdpCopyOffer takes ownership of a detached Storage Access Framework descriptor.
func (c *Core) RdpCopyOffer(token, name string, fd int32) error {
	if fd < 0 {
		return errors.New("invalid source descriptor")
	}
	prepareErr := prepareFileFD(fd)
	src := os.NewFile(uintptr(fd), "rdp-document")
	defer src.Close()
	if prepareErr != nil {
		return prepareErr
	}
	l, agent, id, err := c.rdpCopyAgent(token)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(l.ctx, func() { _ = src.Close() })
	defer stop()
	return agent.CopyOfferDocument(l.ctx, id, name, src)
}

// RdpCopySave writes a selected Windows clipboard file to a user-chosen document.
func (c *Core) RdpCopySave(token, offer string, index int32, fd int32) error {
	if fd < 0 {
		return errors.New("invalid destination descriptor")
	}
	prepareErr := prepareFileFD(fd)
	dst := os.NewFile(uintptr(fd), "rdp-destination")
	defer dst.Close()
	if prepareErr != nil {
		return prepareErr
	}
	l, agent, id, err := c.rdpCopyAgent(token)
	if err != nil {
		return err
	}
	if !l.receiving.CompareAndSwap(false, true) {
		return errors.New("another file is being saved")
	}
	defer l.receiving.Store(false)
	snapshot := agent.CopySnapshot()
	if offer == "" || snapshot.Session != id || snapshot.Offer != offer || index < 0 || int(index) >= len(snapshot.Files) {
		return filetransfer.ErrCopyOfferUnavailable
	}
	stop := context.AfterFunc(l.ctx, func() { _ = dst.Close() })
	defer stop()
	size := snapshot.Files[index].Size
	for offset := int64(0); offset < size; {
		count := int(min(size-offset, 65536))
		data, pending, err := agent.CopyRead(offer, int(index), offset, count)
		if err != nil {
			return err
		}
		if pending {
			select {
			case <-l.ctx.Done():
				return l.ctx.Err()
			case <-time.After(20 * time.Millisecond):
			}
			continue
		}
		if _, err := dst.Write(data); err != nil {
			return err
		}
		offset += int64(len(data))
	}
	return dst.Close()
}
