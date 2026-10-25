package main

import (
	"context"
	"errors"
	"net"
	"strings"

	proto "github.com/calabinet/calabi/pkg/protocol"
	"github.com/calabinet/calabi/pkg/protocol/usererror"
)

// Keep local file/configuration errors useful, and present remote failures
// without RPC envelopes, private connection addresses or duplicate prefixes.
func friendlyCLIError(err error) string {
	if err == nil {
		return ""
	}
	var payload *proto.ErrorPayload
	if errors.As(err, &payload) {
		return payload.UserMessage()
	}
	raw := err.Error()
	code := 0
	var network net.Error
	switch {
	case strings.Contains(raw, "rpc error: code = "):
		code = 500
	case errors.Is(err, context.Canceled):
		code = 499
	case errors.Is(err, context.DeadlineExceeded):
		code = 504
	case errors.As(err, &network):
		code = 502
		if network.Timeout() {
			code = 504
		}
	}
	if code != 0 {
		text, _ := usererror.Message(code, raw)
		return text
	}
	return raw
}
