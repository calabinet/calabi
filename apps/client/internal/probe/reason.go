package probe

// reason.go — a stable classification of WHY a probe failed.
//
// Result.Error carries the operating system's sentence, which is the right
// thing to keep for a detail line but the wrong thing to put in front of a
// user: "connectex: No connection could be made because the target machine
// actively refused it." is Windows telling you nothing is listening. The UI
// needs to say that in the user's language, so it needs a code — not an
// English substring to regex, which would break the moment the OS or the Go
// runtime rewords anything.
//
// Reason is that code. Empty means healthy, or a failure nothing here matched
// (the UI then falls back to showing Error verbatim rather than inventing a
// friendlier lie).

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"syscall"
)

// Failure reasons. Keep these in sync with the `wizard.reason.*` i18n keys in
// apps/client/internal/status/ui/src/i18n/locales/*.json.
const (
	ReasonRefused     = "refused"     // nothing is listening on that address
	ReasonTimeout     = "timeout"     // dialled, no answer in time
	ReasonUnreachable = "unreachable" // no route to that host/network
	ReasonDNS         = "dns"         // the hostname doesn't resolve
	ReasonTLS         = "tls"         // TLS handshake failed (often: it speaks plain HTTP)
	ReasonHTTP5xx     = "http_5xx"    // it answered, with a server error
	ReasonInvalid     = "invalid"     // the address was rejected before we dialled
)

// Winsock error numbers. Windows does NOT report syscall.ECONNREFUSED for a
// refused connection — that constant holds the Unix value there, so
// errors.Is(err, syscall.ECONNREFUSED) is FALSE on Windows even though the
// connection was plainly refused. Verified on this platform: dialling a closed
// loopback port yields errno 10061 with errors.Is == false. So match the raw
// errno against both families instead of trusting the platform constant.
const (
	wsaeconnrefused = 10061
	wsaenetunreach  = 10051
	wsaehostunreach = 10065
	wsaetimedout    = 10060
)

// classifyErr maps a dial/request failure to a Reason, or "" when it doesn't
// fit one of the cases worth wording specially.
func classifyErr(err error) string {
	if err == nil {
		return ""
	}
	// Timeout first: a deadline can surface as a context error, as a net.Error
	// with Timeout(), or as WSAETIMEDOUT, and any of them means the same thing
	// to the reader.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return ReasonTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return ReasonTimeout
	}
	// DNS before the errno checks: a lookup failure wraps no syscall error on
	// some platforms and would otherwise fall through to "".
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return ReasonDNS
	}
	// TLS: a *RecordHeaderError is what you get when the "https" upstream is
	// really serving plain HTTP — by far the most common way this fires, and
	// worth its own sentence.
	var rhe tls.RecordHeaderError
	if errors.As(err, &rhe) {
		return ReasonTLS
	}
	var cve *tls.CertificateVerificationError
	if errors.As(err, &cve) {
		return ReasonTLS
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch {
		case errors.Is(errno, syscall.ECONNREFUSED) || errno == wsaeconnrefused:
			return ReasonRefused
		case errors.Is(errno, syscall.ETIMEDOUT) || errno == wsaetimedout:
			return ReasonTimeout
		case errors.Is(errno, syscall.ENETUNREACH) || errno == wsaenetunreach,
			errors.Is(errno, syscall.EHOSTUNREACH) || errno == wsaehostunreach:
			return ReasonUnreachable
		}
	}
	return ""
}
