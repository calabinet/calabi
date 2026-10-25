import assert from "node:assert/strict";
import { test } from "node:test";
import { peerPresence } from "./peerPresence.ts";

test("presence uses the exact device address and preserves explicit offline vs unknown", () => {
  const nodes = [{overlay:"100.64.0.18",online:true},{overlay:"100.64.0.19",online:false},{overlay:"100.96.0.1",online:true}];
  assert.equal(peerPresence(["100.96.0.1/32","100.64.0.19/32"],nodes),"offline");
  assert.equal(peerPresence(["100.64.0.18/32"],nodes),"online"); // Includes an idle or never-handshaken device.
  assert.equal(peerPresence(["100.96.0.1/32"],nodes),"unknown");
  assert.equal(peerPresence(["100.64.0.18/32"],undefined),"unknown");
  assert.equal(peerPresence(["100.64.0.18/32"],[{overlay:"100.64.0.18"}]),"unknown");
});
