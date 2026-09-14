// errorpage.go — the listener's adapter onto the shared visitor-facing refusal
// page.
//
// The page itself moved to internal/visitorerr so the OAuth gate can render the
// same thing: `listener → policy → oauth` means oauth can never import
// listener, and before the move that asymmetry decided how official a refusal
// looked — an IP block got the branded page, a rejected sign-in got a bare line
// of text. What is left here is the part that is genuinely a listener concern:
// reading Accept off a sniffed request head, and mapping an OpenProxyConn
// failure onto a code.
package listener

import (
	"io"
	"strings"

	"github.com/calabi/calabi/apps/calabi-edge/internal/visitorerr"
)

// upstreamErrCode maps the failure of OpenProxyConn onto a visitor-facing code.
//
// The split that matters: a session BLOCKED for commercial reasons (over the
// monthly traffic cap, suspended) must not be describable from outside. It gets
// the deliberately vague ErrUnavailable; everything else — the client dropped,
// the local target refused — gets ErrUpstreamDown, which tells the owner
// something actionable and tells a stranger nothing they could not already
// infer from the connection failing.
//
// Matching on the error TEXT is not lovely. It is what the current
// session.OpenProxyConn contract offers (a fmt.Errorf), and getting this wrong
// in the safe direction costs a vaguer message, while getting it wrong in the
// other direction publishes a customer's billing state. If that call ever
// returns a typed error, switch to errors.Is and delete this comment.
func upstreamErrCode(err error) string {
	if err != nil && strings.Contains(err.Error(), "session blocked") {
		return visitorerr.ErrUnavailable
	}
	return visitorerr.ErrUpstreamDown
}

// writeVisitorError sends a branded refusal for an HTTP-flavoured listener.
//
// head is the sniffed request head, used ONLY to read Accept — a browser gets
// the page, everything else (curl, a webhook sender, a health check) gets one
// line of text with the same code in it.
func writeVisitorError(w io.Writer, head []byte, httpStatus int, code string) {
	visitorerr.Write(w, visitorerr.Options{
		HTML:       wantsHTML(head),
		Status:     httpStatus,
		StatusText: statusText(httpStatus),
		Code:       code,
	})
}

// wantsHTML reports whether the request looks like it came from a browser.
//
// Deliberately narrow: only an explicit text/html in Accept counts. "*/*"
// (curl's default) does NOT — a terminal full of HTML is worse than a browser
// showing one line of text.
func wantsHTML(head []byte) bool {
	return strings.Contains(strings.ToLower(headerValue(head, "Accept")), "text/html")
}
