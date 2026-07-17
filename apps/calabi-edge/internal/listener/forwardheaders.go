package listener

import (
	"bytes"
	"io"
	"strings"
)

// forwardheaders.go — standard reverse-proxy forwarding headers. The edge
// TERMINATES HTTP/HTTPS, so it stamps the visitor's real source onto the
// request head before forwarding it through the tunnel to the user's backend.
// Without this the backend only ever sees the tunnel-internal peer, never the
// real client IP.
//
// Headers added to every request (request #1 + every keep-alive request):
//
//	X-Forwarded-For    the connecting IP APPENDED to any existing chain. Per
//	                   the de-facto spec the ORIGINAL client is leftmost and
//	                   each proxy appends the peer it received from — so a
//	                   fronting CDN/LB's chain is preserved and the edge adds
//	                   the IP it actually saw at the END (NOT the front).
//	X-Real-IP          the connecting IP, OVERWRITTEN — the edge is the trust
//	                   boundary, so this is the one value a backend can rely on
//	                   even if a direct client spoofed an inbound X-Real-IP.
//	X-Forwarded-Proto  http|https — the scheme the visitor used to reach the
//	                   edge. Set only when ABSENT so a TLS-terminating CDN in
//	                   front keeps its (more accurate) value.
//	X-Forwarded-Host   the original Host. Set only when ABSENT (same reason).
//
// Always on, both editions. A per-tunnel header-rewrite rule runs AFTER this
// (see the transform composed in http.go/https.go), so an operator who wants
// different behavior — e.g. strip X-Forwarded-For — can still override it.
//
// Framing headers (Content-Length / Transfer-Encoding) are never touched, so
// body framing and per-request counting stay correct.

// injectForwardHeaders returns head with the forwarding headers applied. head is
// a raw HTTP/1.1 request head (request line + header lines + blank terminator);
// output is normalized to CRLF. Empty visitorIP → head returned unchanged.
func injectForwardHeaders(head []byte, visitorIP, host string, https bool) []byte {
	if visitorIP == "" || len(head) == 0 {
		return head
	}
	lines := strings.Split(string(head), "\n")
	if len(lines) == 0 {
		return head
	}
	scheme := "http"
	if https {
		scheme = "https"
	}
	var b strings.Builder
	b.Grow(len(head) + 128)
	b.WriteString(strings.TrimRight(lines[0], "\r")) // request line
	b.WriteString("\r\n")

	var sawXFF, sawRealIP, sawProto, sawHost bool
	for _, ln := range lines[1:] {
		t := strings.TrimRight(ln, "\r")
		if t == "" {
			break // blank line → end of headers
		}
		colon := strings.IndexByte(t, ':')
		if colon <= 0 {
			b.WriteString(t) // malformed → keep verbatim (fail-safe)
			b.WriteString("\r\n")
			continue
		}
		switch strings.ToLower(strings.TrimSpace(t[:colon])) {
		case "x-forwarded-for":
			existing := strings.TrimSpace(t[colon+1:])
			b.WriteString("X-Forwarded-For: ")
			if existing != "" {
				b.WriteString(existing)
				b.WriteString(", ")
			}
			b.WriteString(visitorIP)
			b.WriteString("\r\n")
			sawXFF = true
		case "x-real-ip":
			// Drop the inbound value; we re-stamp it authoritatively below.
			sawRealIP = true
			b.WriteString("X-Real-IP: ")
			b.WriteString(visitorIP)
			b.WriteString("\r\n")
		case "x-forwarded-proto":
			sawProto = true
			b.WriteString(t) // preserve a fronting proxy's value
			b.WriteString("\r\n")
		case "x-forwarded-host":
			sawHost = true
			b.WriteString(t) // preserve a fronting proxy's value
			b.WriteString("\r\n")
		default:
			b.WriteString(t)
			b.WriteString("\r\n")
		}
	}
	if !sawXFF {
		b.WriteString("X-Forwarded-For: ")
		b.WriteString(visitorIP)
		b.WriteString("\r\n")
	}
	if !sawRealIP {
		b.WriteString("X-Real-IP: ")
		b.WriteString(visitorIP)
		b.WriteString("\r\n")
	}
	if !sawProto {
		b.WriteString("X-Forwarded-Proto: ")
		b.WriteString(scheme)
		b.WriteString("\r\n")
	}
	if !sawHost && host != "" {
		b.WriteString("X-Forwarded-Host: ")
		b.WriteString(host)
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n") // terminator
	return []byte(b.String())
}

// headTransformReader applies `transform` to each request head on a keep-alive
// visitor→client byte stream (requests #2.N; request #1's head is transformed
// by the caller before replay). Bodies pass through verbatim. It mirrors
// requestCounter's framing + fail-open contract: on ANY ambiguity (chunked /
// upgrade / runaway head / EOF mid-head) it switches to verbatim passthrough and
// stops transforming — it can never corrupt a body or break the connection. The
// transform must not change framing headers (Content-Length / Transfer-Encoding)
// — injectForwardHeaders and policy header-rewrite both honor that.
type headTransformReader struct {
	src       io.Reader
	transform func([]byte) []byte

	st         rcState
	bodyLeft   int64
	head       []byte
	out        bytes.Buffer
	buf        []byte
	pendingErr error
}

// wrapHeadTransform primes the reader to begin AFTER request #1's head, seeding
// framing state from request #1 so request #2's head is located correctly.
func wrapHeadTransform(src io.Reader, transform func([]byte) []byte, firstHead []byte) io.Reader {
	st, bodyLeft := nextStateFor(firstHead)
	return &headTransformReader{src: src, transform: transform, st: st, bodyLeft: bodyLeft, buf: make([]byte, 32*1024)}
}

func (r *headTransformReader) Read(p []byte) (int, error) {
	if r.out.Len() > 0 {
		return r.out.Read(p)
	}
	if r.pendingErr != nil {
		return 0, r.pendingErr
	}
	for r.out.Len() == 0 {
		n, err := r.src.Read(r.buf)
		if n > 0 {
			r.process(r.buf[:n])
		}
		if err != nil {
			if len(r.head) > 0 { // flush an incomplete trailing head verbatim
				r.out.Write(r.head)
				r.head = nil
			}
			r.pendingErr = err
			break
		}
	}
	if r.out.Len() > 0 {
		return r.out.Read(p)
	}
	return 0, r.pendingErr
}

func (r *headTransformReader) process(data []byte) {
	for len(data) > 0 {
		switch r.st {
		case rcPass:
			r.out.Write(data)
			return
		case rcBody:
			if int64(len(data)) <= r.bodyLeft {
				r.out.Write(data)
				r.bodyLeft -= int64(len(data))
				return
			}
			r.out.Write(data[:r.bodyLeft])
			data = data[r.bodyLeft:]
			r.bodyLeft = 0
			r.st = rcHead
		case rcHead:
			i := 0
			advanced := false
			for i < len(data) {
				r.head = append(r.head, data[i])
				i++
				if len(r.head) > rcMaxHead { // runaway header → fail open
					r.out.Write(r.head)
					r.head = nil
					r.st = rcPass
					r.out.Write(data[i:])
					return
				}
				if endsWithHeaderTerminator(r.head) {
					// Body framing is read from the ORIGINAL head (the transform
					// never touches framing headers); the head is emitted
					// transformed.
					cl, chunked, upgrade := parseBodyFraming(r.head)
					r.out.Write(r.transform(r.head))
					r.head = nil
					switch {
					case upgrade || chunked || cl < 0:
						r.st = rcPass
						r.out.Write(data[i:])
						return
					case cl == 0:
						r.st = rcHead
					default:
						r.st = rcBody
						r.bodyLeft = cl
					}
					advanced = true
					break
				}
			}
			if advanced {
				data = data[i:]
			} else {
				return // consumed the whole chunk into the in-progress head
			}
		}
	}
}
