// Package visitorerr is what a visitor sees when the edge refuses or cannot
// serve a request.
//
// It lives in its own package because it is not a listener concern: the OAuth
// gate refuses people too, and `listener → policy → oauth` means oauth can
// never import listener. Before this, the branded page was reachable from one
// of those two and the other wrote a bare line of text — so how official a
// refusal looked depended on which policy said no.
//
// Two things here are not cosmetic:
//
//  1. A STABLE CODE. Every refusal carries one, so a user can search for it and
//     support can answer without a back-and-forth about what the page said. The
//     prose can be reworded freely; the code is the contract.
//
//  2. NOT LEAKING WHY. Each code's body is written for the least-privileged
//     reader. The precise reason stays in the edge's logs and in the owner's
//     console — a stranger who types the hostname must not learn the customer's
//     commercial state.
//
// LANGUAGE. English only, deliberately. The visitor is an arbitrary person on
// the internet whose language we do not know, and the CODE is the part that
// works in every language. The console — where the owner reads the same
// condition — is translated.
package visitorerr

import (
	"bytes"
	"fmt"
	"io"
	"strings"
)

// Visitor-facing error codes. Stable and never reused: a code that changed
// meaning would make every old support thread and search result wrong.
const (
	// ErrNoTunnel — nothing is serving this hostname right now. By far the most
	// common one, and the only one whose body is aimed at the tunnel's OWNER as
	// well as the visitor: during development they are usually the same person.
	ErrNoTunnel = "CAL-1001"
	// ErrUpstreamDown — the tunnel is connected but the edge could not open a
	// stream to the client, or the client could not reach its local target.
	ErrUpstreamDown = "CAL-1002"
	// ErrIPBlocked — refused by the tunnel owner's IP allow/deny rules.
	ErrIPBlocked = "CAL-1003"
	// ErrRateLimited — refused by the tunnel owner's own connection-rate cap.
	ErrRateLimited = "CAL-1004"
	// ErrConnLimit — too many connections open for this organization.
	ErrConnLimit = "CAL-1005"
	// ErrDailyCap — this tunnel's daily request allowance is spent.
	ErrDailyCap = "CAL-1006"
	// ErrUnavailable — deliberately vague. Used where the real reason is the
	// customer's commercial state (over the monthly traffic cap, suspended).
	// A visitor is not entitled to that, and the owner reads it in the console.
	ErrUnavailable = "CAL-1007"
	// ErrAuthRequired — the tunnel is behind Basic auth and the request had no
	// usable credentials. Rendered WITH the WWW-Authenticate header, never
	// instead of it: drop the header and the browser stops prompting.
	ErrAuthRequired = "CAL-1008"
	// ErrSignInDenied — the visitor signed in with the identity provider and
	// the account is not on the tunnel's allow list. An answer about THEM, so
	// it is safe to be specific: they already proved who they are.
	ErrSignInDenied = "CAL-1009"
	// ErrSignInFailed — the sign-in round trip itself did not complete (stale
	// state, the provider refused the exchange). Distinct from ErrSignInDenied
	// because the fix is different: retry, versus ask the owner for access.
	ErrSignInFailed = "CAL-1010"
	// ErrInternal — our fault. Says so.
	ErrInternal = "CAL-1500"
)

// Body is what each code shows. Headline is the one line a visitor reads;
// Detail is the paragraph under it, and may be empty.
type Body struct {
	Headline string
	Detail   string
}

// Bodies is exported so a test can enumerate every code rather than restating
// the list — a hand-kept list is how a new code ships with no page at all.
var Bodies = map[string]Body{
	ErrNoTunnel: {
		"This tunnel is offline",
		"Nothing is currently serving this address. If it is yours, check that the Calabi client on the machine behind it is running and connected.",
	},
	ErrUpstreamDown: {
		"The tunnel is connected, but its target did not answer",
		"The Calabi client is online, but the local address it forwards to refused the connection. If it is yours, check that the service on that machine is listening.",
	},
	ErrIPBlocked: {
		"Your address is not allowed here",
		"This tunnel only accepts connections from addresses its owner has permitted.",
	},
	ErrRateLimited: {
		"Too many connections, too quickly",
		"This tunnel has a rate limit set by its owner. Wait a moment and try again.",
	},
	ErrConnLimit: {
		"Too many connections open",
		"This organization has reached the number of connections it may hold open at once. Try again shortly.",
	},
	ErrDailyCap: {
		"This tunnel has reached its daily request limit",
		"The limit resets at the start of the next UTC day.",
	},
	ErrUnavailable: {
		"This tunnel is temporarily unavailable",
		"Its owner can see the reason in the Calabi console.",
	},
	ErrAuthRequired: {
		"This tunnel asks for a username and password",
		"Its owner protected it with a sign-in. Enter the credentials they gave you; if you do not have them, ask whoever shared this address.",
	},
	ErrSignInDenied: {
		"That account is not permitted here",
		"You signed in successfully, but this tunnel only accepts certain accounts. Ask its owner to allow yours.",
	},
	ErrSignInFailed: {
		"Sign-in did not complete",
		"The round trip to the identity provider did not finish — often just an expired link. Go back to the address you started from and try again.",
	},
	ErrInternal: {
		"Something went wrong on our side",
		"This is not your fault and not the tunnel owner's. If it persists, quote the code below.",
	},
}

// Options is one refusal, as the caller knows it.
type Options struct {
	// HTML renders the page; false writes one line of text with the same code
	// in it. Callers decide from the request's Accept header — guessing wrong
	// in the text direction is harmless, guessing wrong in the HTML direction
	// fills a terminal with markup.
	HTML       bool
	Status     int
	StatusText string
	Code       string
	// ExtraHeaders is appended verbatim, each line CRLF-terminated. Its one
	// user is the Basic-auth challenge: that response needs a real body AND its
	// WWW-Authenticate header, because without the header the browser never
	// prompts and the page becomes a dead end instead of a door.
	ExtraHeaders string
}

// Write sends a refusal. An unknown code falls back to ErrInternal rather than
// rendering a blank page.
func Write(w io.Writer, o Options) {
	body, ok := Bodies[o.Code]
	if !ok {
		body, o.Code = Bodies[ErrInternal], ErrInternal
	}
	if o.StatusText == "" {
		o.StatusText = "Status"
	}
	if o.HTML {
		writeHTML(w, o, body)
		return
	}
	writeText(w, o, body)
}

// headers are sent with every refusal, whatever the shape.
//
//   - no-store, because a browser that cached a 502 would keep showing it after
//     the tunnel came back, and the user would report a bug that is not one.
//   - noindex, because a search engine that indexed these would put "This
//     tunnel is offline" in results for the customer's own hostname.
//   - close, because whatever went wrong, this connection is finished.
func headers(extra string) string {
	return "Cache-Control: no-store, no-cache, must-revalidate\r\n" +
		"Pragma: no-cache\r\n" +
		"X-Robots-Tag: noindex, nofollow\r\n" +
		"Connection: close\r\n" +
		extra
}

func writeText(w io.Writer, o Options, body Body) {
	text := fmt.Sprintf("%s\n\n%s\n\nError code: %s\n", body.Headline, body.Detail, o.Code)
	fmt.Fprintf(w,
		"HTTP/1.1 %d %s\r\n"+
			"Content-Type: text/plain; charset=utf-8\r\n"+
			"Content-Length: %d\r\n"+
			"%s\r\n%s",
		o.Status, o.StatusText, len(text), headers(o.ExtraHeaders), text)
}

func writeHTML(w io.Writer, o Options, body Body) {
	var b bytes.Buffer
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width,initial-scale=1">`)
	b.WriteString(`<meta name="robots" content="noindex,nofollow">`)
	b.WriteString(`<title>`)
	b.WriteString(htmlEscape(body.Headline))
	b.WriteString(`</title><style>`)
	b.WriteString(css)
	b.WriteString(`</style></head><body><main>`)
	b.WriteString(warnIcon)
	b.WriteString(`<div class="t">`)
	b.WriteString(`<p class="s">` + fmt.Sprintf("%d", o.Status) + ` ` + htmlEscape(o.StatusText) + `</p>`)
	b.WriteString(`<h1>` + htmlEscape(body.Headline) + `</h1>`)
	if body.Detail != "" {
		b.WriteString(`<p class="d">` + htmlEscape(body.Detail) + `</p>`)
	}
	b.WriteString(`<p class="c">` + htmlEscape(o.Code) + `</p>`)
	b.WriteString(`</div>`)
	b.WriteString(`</main></body></html>`)

	fmt.Fprintf(w,
		"HTTP/1.1 %d %s\r\n"+
			"Content-Type: text/html; charset=utf-8\r\n"+
			"Content-Length: %d\r\n"+
			"%s\r\n",
		o.Status, o.StatusText, b.Len(), headers(o.ExtraHeaders))
	_, _ = w.Write(b.Bytes())
}

// warnIcon is Ant Design's WarningFilled glyph, inlined — the same mark, at
// the same 72px, that the console shows when a quota is spent, so the two
// surfaces agree about what a warning looks like. Path copied from
// @ant-design/icons-svg, not redrawn.
//
// Inline because this page is served when something is already broken: it must
// not depend on a stylesheet, a font, an icon set or a CDN that could be
// unreachable for the same reason the tunnel is. aria-hidden because it repeats
// what the headline already says.
const warnIcon = `<svg class="i" viewBox="64 64 896 896" aria-hidden="true" focusable="false">` +
	`<path d="M955.7 856l-416-720c-6.2-10.7-16.9-16-27.7-16s-21.6 5.3-27.7 16l-416 720C56 877.4 71.4 904 96 904h832c24.6 0 40-26.6 27.7-48zM480 416c0-4.4 3.6-8 8-8h48c4.4 0 8 3.6 8 8v184c0 4.4-3.6 8-8 8h-48c-4.4 0-8-3.6-8-8V416zm32 352a48.01 48.01 0 010-96 48.01 48.01 0 010 96z"/>` +
	`</svg>`

// css is inline and tiny on purpose — same reason as the icon. It follows the
// visitor's own light/dark setting rather than picking one.
const css = `:root{color-scheme:light dark}` +
	`*{box-sizing:border-box}` +
	`body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;` +
	`font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;` +
	`background:#fafafa;color:#1a1a1a;padding:24px}` +
	`@media(prefers-color-scheme:dark){body{background:#141414;color:#e8e8e8}}` +
	`main{max-width:38rem;text-align:left;display:flex;gap:24px;align-items:center}` +
	`.t{min-width:0}` +
	// 72px is Ant Design's Result icon size (fontSizeHeading3 * 3), so this mark
	// is the same size as the one the console shows when a quota runs out.
	`.i{width:72px;height:72px;flex:none;fill:#faad14}` +
	`@media(max-width:30rem){main{gap:16px}.i{width:48px;height:48px}}` +
	`.s{margin:0 0 4px;font-size:13px;letter-spacing:.08em;text-transform:uppercase;opacity:.5}` +
	`h1{margin:0 0 12px;font-size:24px;font-weight:600;line-height:1.3}` +
	`.d{margin:0 0 24px;opacity:.75}` +
	`.c{margin:0;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px;opacity:.5}`

// htmlEscape is a local minimal escaper. The strings it handles are our own
// constants plus a status text, so nothing attacker-controlled reaches it
// today — it exists so that stays true if somebody later interpolates a host.
func htmlEscape(s string) string {
	return strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#39;",
	).Replace(s)
}
