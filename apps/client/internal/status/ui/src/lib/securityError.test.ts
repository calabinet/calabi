// Run with: node --test src/lib/securityError.test.ts   (node >= 22 strips the types)
import { test } from "node:test";
import assert from "node:assert/strict";
import { securityErrorText, type TFn } from "./securityError.ts";

// A t() that shows which key and which values it was asked for.
const t: TFn = (key, opts) => (opts ? `${key} ${JSON.stringify(opts)}` : key);
const ctx = { hideCommerce: false, typeName: "TCP" };

test("a plan refusal becomes the drawer's own locked-features sentence, naming the feature", () => {
  assert.equal(
    securityErrorText(t, "rate_limit_requires_upgrade", undefined, ctx),
    'tunnels.security.lockedNotice {"features":"tunnels.rateLimit.title"}',
  );
  assert.equal(
    securityErrorText(t, "oauth_requires_upgrade", undefined, ctx),
    'tunnels.security.lockedNotice {"features":"tunnels.oauth.title"}',
  );
});

test("every plan gate the server has a code for is covered", () => {
  for (const code of [
    "ip_policy_requires_upgrade",
    "basic_auth_requires_upgrade",
    "rate_limit_requires_upgrade",
    "header_rewrite_requires_upgrade",
    "oauth_requires_upgrade",
  ]) {
    assert.match(securityErrorText(t, code, undefined, ctx) ?? "", /lockedNotice/, code);
  }
});

test("a platform that hides its commerce entry points says to ask the administrator", () => {
  const out = securityErrorText(t, "header_rewrite_requires_upgrade", undefined, { ...ctx, hideCommerce: true });
  assert.match(out ?? "", /lockedNoticeContact/);
});

test("a raw-port refusal reuses the type note, with the type's own name", () => {
  for (const code of ["basic_auth_not_for_bare_port", "oauth_not_for_bare_port", "header_rewrite_not_for_bare_port"]) {
    assert.equal(securityErrorText(t, code, undefined, { ...ctx, typeName: "TLS" }), 'tunnels.security.barePortNote {"type":"TLS"}');
  }
});

test("validation refusals carry the offending value", () => {
  assert.equal(securityErrorText(t, "ip_policy_invalid_cidr", "10.0.0.0/99", ctx), 'tunnels.security.err.ipInvalid {"value":"10.0.0.0/99"}');
  assert.equal(securityErrorText(t, "header_forbidden", "Connection", ctx), 'tunnels.security.err.headerForbidden {"value":"Connection"}');
  assert.equal(securityErrorText(t, "header_invalid_name", "Bad Name", ctx), 'tunnels.security.err.headerName {"value":"Bad Name"}');
  assert.equal(securityErrorText(t, "oauth_missing_credentials", undefined, ctx), "tunnels.security.err.oauthCredentials");
});

test("a code it does not know is left to the caller (null), never swallowed", () => {
  assert.equal(securityErrorText(t, "something_new", undefined, ctx), null);
  assert.equal(securityErrorText(t, undefined, undefined, ctx), null);
  assert.equal(securityErrorText(t, 403, undefined, ctx), null);
});
