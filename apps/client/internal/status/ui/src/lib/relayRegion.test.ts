// Run with: node --test src/lib/relayRegion.test.ts   (node >= 22 strips the types)
import { test } from "node:test";
import assert from "node:assert/strict";
import { relayOwner, relayOwnerKind } from "./relayRegion.ts";

test("a self- region is the org's own relay, shown without the marker", () => {
  assert.deepEqual(relayOwner("self-office"), { self: true, label: "office" });
  // The label itself may contain dashes; only the leading marker is stripped.
  assert.deepEqual(relayOwner("self-ap-singapore"), { self: true, label: "ap-singapore" });
});

test("any other region is the platform's", () => {
  assert.deepEqual(relayOwner("ap-singapore"), { self: false, label: "ap-singapore" });
  // A platform region that merely CONTAINS the word is not the org's.
  assert.deepEqual(relayOwner("us-self-serve"), { self: false, label: "us-self-serve" });
});

// An unknown region must not read as "platform": an older daemon reports none,
// and so does a direct path. Guessing would label somebody's own relay as ours.
test("no region is no answer", () => {
  assert.equal(relayOwner(""), null);
  assert.equal(relayOwner("   "), null);
  assert.equal(relayOwner(undefined), null);
  assert.equal(relayOwner(null), null);
});

test("on the platform a relay is labelled the org's own or the platform's", () => {
  assert.equal(relayOwnerKind(relayOwner("self-office"), false), "self");
  assert.equal(relayOwnerKind(relayOwner("ap-singapore"), false), "platform");
  assert.equal(relayOwnerKind(relayOwner(""), false), null);
});

// A self-hosted coordinator names its relays with bare codes: there is no
// "self-" marker because there is nothing to tell them apart from. Labelling by
// the code would put "Platform relay" on the administrator's own machine.
test("on a self-hosted server no relay is labelled with an owner", () => {
  assert.equal(relayOwnerKind(relayOwner("sg"), true), null);
  assert.equal(relayOwnerKind(relayOwner("self-office"), true), null);
  assert.equal(relayOwnerKind(relayOwner(""), true), null);
});
