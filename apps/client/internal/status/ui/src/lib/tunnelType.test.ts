import { test } from "node:test";
import assert from "node:assert/strict";

import { clientTlsOffer, typeLabel } from "./tunnelType.ts";

// The wire type `sni` is called TLS on screen; nothing else is renamed.
test("typeLabel", () => {
  assert.equal(typeLabel("sni"), "TLS");
  assert.equal(typeLabel("SNI"), "TLS");
  assert.equal(typeLabel("https"), "HTTPS");
  assert.equal(typeLabel("tcp"), "TCP");
  assert.equal(typeLabel(""), "");
  assert.equal(typeLabel(undefined), "");
});

// On the platform the tunnel lands on the node this daemon is connected to, so
// that node is the one that has to take TLS endpoints.
// Each refusal names one missing
// thing, in the order a user would have to fix them.
test("clientTlsOffer on the platform", () => {
  const ok = { standalone: false, httpsPort: 443, onOwnEdge: true, edgeTakesTls: true, parentDomains: 1 };
  assert.equal(clientTlsOffer(ok), "ok");
  assert.equal(clientTlsOffer({ ...ok, onOwnEdge: false, edgeTakesTls: false }), "needsOwnNode");
  // A platform node reporting tls_passthrough (sni_port) is still not the org's.
  assert.equal(clientTlsOffer({ ...ok, onOwnEdge: false }), "needsOwnNode");
  assert.equal(clientTlsOffer({ ...ok, edgeTakesTls: false }), "needsUpgrade");
  assert.equal(clientTlsOffer({ ...ok, parentDomains: 0 }), "needsDomain");
  // Not a plan tier: nothing about the plan goes in.
});

// Standalone: the node is the user's own, and it passes TLS through on its
// HTTPS port — which is the one thing that can be missing.
test("clientTlsOffer standalone", () => {
  const base = { standalone: true, onOwnEdge: false, edgeTakesTls: false, parentDomains: 0 };
  assert.equal(clientTlsOffer({ ...base, httpsPort: 443 }), "ok");
  assert.equal(clientTlsOffer({ ...base, httpsPort: 0 }), "needsHttpsPort");
  assert.equal(clientTlsOffer({ ...base }), "needsHttpsPort");
});
