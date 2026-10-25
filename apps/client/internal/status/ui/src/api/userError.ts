// Kept identical in the independently built console, admin and daemon bundles.
// error_key is additive: older servers are handled by the legacy fallback.
import { matchBusiness, renderBusiness, businessHints } from "./businessError.ts";
const english = {
  invalid: "Please check the information you entered and try again.",
  unauthenticated: "Your session has expired. Please sign in again.",
  forbidden: "You do not have permission to perform this action. Contact your organization administrator if you need access.",
  notFound: "The requested item could not be found. It may have been removed. Refresh the page and try again.",
  conflict: "This item already exists or has changed. Refresh the page and try again.",
  quota: "A usage or request limit has been reached. Check your available quota or wait a moment before trying again.",
  precondition: "This action is not available in the current state. Refresh the page and check the requirements.",
  unsupported: "This feature is not available on this server. Check that your client and server are up to date.",
  timeout: "The request took too long. Please try again in a moment.",
  unavailable: "The service is temporarily unavailable. Please try again in a moment.",
  internal: "We could not complete your request. Please try again. If the problem continues, contact support.",
  cancelled: "The request was cancelled. Please try again if needed.",
  invalidCredentials: "The email address or password is incorrect. Please check them and try again.",
  emailNotVerified: "Please verify your email address before signing in. Check your inbox for the verification email.",
  emailExists: "This email address is already registered. Sign in or reset your password.",
  insufficientBalance: "Your balance is insufficient. Add funds or choose another payment method.",
  network: "Could not connect to the service. Check your network connection and try again.",
};

type Key = keyof typeof english;
type Translate = (key: string, options: { defaultValue: string }) => string;

// Background jobs report failures inside otherwise successful responses.
export function displayError(raw: unknown, t?: Translate): string {
  return friendlyError(raw, 400, undefined, t);
}
const statusKeys: Record<number, Key> = {
  400: "invalid", 401: "unauthenticated", 403: "forbidden", 404: "notFound",
  408: "timeout", 409: "conflict", 412: "precondition", 422: "invalid",
  429: "quota", 499: "cancelled", 501: "unsupported", 502: "unavailable",
  503: "unavailable", 504: "timeout",
};
const reasons: Record<string, Key> = {
  "invalid credentials": "invalidCredentials", "invalid email or password": "invalidCredentials",
  "email not verified": "emailNotVerified", "email already registered": "emailExists",
  "email already exists": "emailExists", "insufficient balance": "insufficientBalance",
  "赠金与余额不足，请先充值后再支付": "insufficientBalance",
  "missing bearer token": "unauthenticated", "invalid bearer token": "unauthenticated",
  "not authenticated": "unauthenticated", "invalid token": "unauthenticated",
  "insufficient role": "forbidden", "rate limited": "quota",
};

export function friendlyError(
  raw: unknown, status?: number, key?: unknown, t?: Translate, transportCode?: string, args?: unknown,
): string {
  const render = (k: Key) => t ? t(`apiErrors.${k}`, { defaultValue: english[k] }) : english[k];
  let msg = typeof raw === "string" ? raw.trim() : "";
  while (msg.includes("rpc error: code = ")) {
    const match = /rpc error: code = (\w+) desc = ([\s\S]*)/.exec(msg);
    if (!match) return render(statusKeys[status ?? 500] || "internal");
    const grpcKeys: Record<string, Key> = {
      Unavailable: "unavailable", DeadlineExceeded: "timeout", Internal: "internal",
      Unknown: "internal", DataLoss: "internal", Unimplemented: "unsupported", Canceled: "cancelled",
    };
    if (Object.prototype.hasOwnProperty.call(grpcKeys, match[1])) return render(grpcKeys[match[1]]);
    msg = match[2];
  }
  const business = status && status < 500 ? renderBusiness(key, args, t) : null;
  if (business) return business;
  if (typeof key === "string" && Object.prototype.hasOwnProperty.call(english, key)) return render(key as Key);
  const reason = Object.prototype.hasOwnProperty.call(reasons, msg.toLowerCase()) ? reasons[msg.toLowerCase()] : undefined;
  if (reason) return render(reason);
  if (status && status < 500) {
    const known = matchBusiness(msg);
    if (known) return renderBusiness(known.key, known.args, t)!;
  }
  for (const [k, text] of Object.entries(english)) if (msg === text) return render(k as Key);
  if (transportCode === "ECONNABORTED" || transportCode === "ETIMEDOUT") return render("timeout");
  if (transportCode === "ERR_CANCELED") return render("cancelled");
  if (!status) return render("network");
  if (/dial (tcp|unix)|connection (refused|reset)|transport:|x509:|tls:/i.test(msg)) return render("unavailable");
  if (status >= 500 || !msg || /[\r\n<>\u3400-\u9fff]|dial (tcp|unix)|connection (refused|reset)|transport:|sql:|sqlstate|pq:|ent:|x509:|tls:|unexpected eof|upstream|decode body:|json:|context (deadline|canceled)|^HTTP \d+|^Request failed with status code/i.test(msg)) {
    return render(/deadline|timeout/i.test(msg) ? "timeout" : statusKeys[status] || "internal");
  }
  return render(statusKeys[status] || "invalid");
}

// Enrich the stable reason before translating. Login and unlock flows must
// inspect these fields rather than matching text in the viewer's language.
export function formatError(
  data: unknown, status?: number, t?: Translate, transportCode?: string, fallback?: string,
): string {
  const body = data && typeof data === "object" && !Array.isArray(data) ? data as Record<string, unknown> : undefined;
  const raw = body?.error ?? data ?? fallback;
  if (body && !body.error_key && /email not verified/i.test(String(raw))) body.error_key = "emailNotVerified";
  if (body && status && status < 500) {
    const existing = renderBusiness(body.error_key, body.error_args);
    if (!existing) {
      const known = matchBusiness(raw, body.code);
      if (known) { body.error_key = known.key; body.error_args = known.args; }
    }
  }
  let text = friendlyError(raw, status, body?.error_key, t, transportCode, body?.error_args);
  if (body) {
    for (const hint of businessHints(body, t)) if (!text.endsWith(hint)) text += " " + hint;
  }
  return text;
}
