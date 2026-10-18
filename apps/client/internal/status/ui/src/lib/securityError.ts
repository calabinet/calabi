// securityError.ts — the server's refusals of a security save, in the viewer's
// language.
//
// bff-console answers these with a fixed Chinese sentence plus a stable `code`.
// Shown as-is, an English or Japanese dashboard put a Chinese toast on a failed
// save — and for the plan gates, the sentence names a feature the drawer may not
// even be showing. The code is the contract, so the message is rebuilt here from
// it; a code this table does not know returns null and the caller shows the
// server's own text rather than nothing.
//
// Run with: node --test src/lib/securityError.test.ts   (node >= 22 strips the types)

export type TFn = (key: string, opts?: Record<string, unknown>) => string;

// *_requires_upgrade → the feature's title. The sentence around it is the drawer's
// own "plan locks this" notice, which already has the contact-your-admin variant
// for platforms that hide their commerce entry points.
const PLAN_GATED: Record<string, string> = {
  ip_policy_requires_upgrade: "tunnels.ipPolicy.title",
  basic_auth_requires_upgrade: "tunnels.basicAuth.title",
  rate_limit_requires_upgrade: "tunnels.rateLimit.title",
  header_rewrite_requires_upgrade: "tunnels.headers.title",
  oauth_requires_upgrade: "tunnels.oauth.title",
};

// Refused by the endpoint's type, not the plan: a raw port cannot apply them.
const BARE_PORT = new Set([
  "basic_auth_not_for_bare_port",
  "oauth_not_for_bare_port",
  "header_rewrite_not_for_bare_port",
]);

export function securityErrorText(
  t: TFn,
  code: unknown,
  value: unknown,
  ctx: { hideCommerce: boolean; typeName: string },
): string | null {
  if (typeof code !== "string" || !code) return null;
  const title = PLAN_GATED[code];
  if (title) {
    return t(ctx.hideCommerce ? "tunnels.security.lockedNoticeContact" : "tunnels.security.lockedNotice", {
      features: t(title),
    });
  }
  if (BARE_PORT.has(code)) return t("tunnels.security.barePortNote", { type: ctx.typeName });
  const v = typeof value === "string" ? value : "";
  switch (code) {
    case "ip_policy_invalid_cidr":
      return t("tunnels.security.err.ipInvalid", { value: v });
    case "header_invalid_name":
      return t("tunnels.security.err.headerName", { value: v });
    case "header_forbidden":
      return t("tunnels.security.err.headerForbidden", { value: v });
    case "oauth_missing_credentials":
      return t("tunnels.security.err.oauthCredentials");
  }
  return null;
}
