package main

// register_error.go — what to print when the edge refuses to register a tunnel.
//
// Most refusals are faults: a port is taken, a domain is blacklisted, the plan
// does not include this type. Two are not — they are the organization's own
// rules answering — and printing those through the generic path gives the
// person at the terminal a transport envelope and a code where a sentence
// belongs:
//
//	calabi: register tunnel: calabi: code=3009 tunnel awaiting approval: an admin …
//
// The codes are the contract (pkg/protocol), not the wording: the edge may
// reword its message, and a client that matched on text would go quiet the day
// it did.

import (
	"errors"
	"fmt"
	"strings"

	proto "github.com/calabinet/calabi/pkg/protocol"
)

// registerRefusal returns a sentence for a NEW_PROXY refusal that is a policy
// answer rather than a fault, and "" for everything else — callers fall back to
// their normal error printing, which is right for a real failure.
//
// The second return says whether the tunnel row SURVIVED the refusal. Waiting
// for approval keeps it (that is the whole point: an admin has something to
// look at), so "run it again once it is approved" is honest advice. A policy
// refusal does not, and telling somebody to re-run without changing anything
// would be a loop.
func registerRefusal(err error) (string, bool) {
	var pe *proto.ErrorPayload
	if !errors.As(err, &pe) || pe == nil {
		return "", false
	}
	switch pe.Code {
	case proto.CodeProxyAwaitingApproval:
		return "this organization reviews the tunnels its members create, so this one is " +
			"waiting for an admin to approve it. It has been saved — ask an admin to " +
			"approve it in the console (Tunnels → Settings), then run this again.", true
	case proto.CodeProxyPolicyRequired:
		// The edge carries the control plane's own sentence, which names the rule
		// that applied and the ways out — printed as it is. A fixed "requires
		// every tunnel to have access protection" in front of it doubled the
		// sentence for that rule and contradicted the other one, which is about
		// raw-port tunnels only. The code still decides that this is a policy
		// answer; only the words come from the edge.
		if strings.TrimSpace(pe.MessageEN) != "" {
			return pe.UserMessage(), false
		}
		return "this organization requires access protection on this tunnel; " +
			"ask an owner or admin of the organization what its rule is.", false
	}
	return "", false
}

// printRegisterError writes a refusal without its transport or diagnostic prefix.
func printRegisterError(w interface{ Write([]byte) (int, error) }, err error) {
	if msg, _ := registerRefusal(err); msg != "" {
		fmt.Fprintln(w, "calabi:", msg)
		return
	}
	fmt.Fprintln(w, "calabi: register tunnel:", friendlyCLIError(err))
}
