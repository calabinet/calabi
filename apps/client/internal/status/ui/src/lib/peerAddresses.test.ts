import assert from "node:assert/strict";
import { test } from "node:test";
import { peerAddresses } from "./peerAddresses.ts";

test("identify the device address independently of WireGuard prefix order", () => {
  assert.deepEqual(peerAddresses(["192.168.1.22/32", "100.96.0.22/32", "100.64.0.7/32", "192.168.1.0/24"]), {
    overlay: "100.64.0.7", routes: ["192.168.1.22/32", "100.96.0.22/32", "192.168.1.0/24"], exits: [],
  });
});
test("separate exit defaults from subnets while keeping IPv6 subnet prefixes", () => {
  assert.deepEqual(peerAddresses(["0.0.0.0/0", "::/0", "100.95.255.254/32", "fd00::1/128"]), {
    overlay: "100.95.255.254", routes: ["fd00::1/128"], exits: ["0.0.0.0/0", "::/0"],
  });
});
test("missing device addresses never fall back to a subnet or alias", () => {
  assert.deepEqual(peerAddresses(["100.96.0.7/32", "192.168.1.7/32"]), { overlay: "", routes: ["100.96.0.7/32", "192.168.1.7/32"], exits: [] });
  assert.deepEqual(peerAddresses(), { overlay: "", routes: [], exits: [] });
  assert.deepEqual(peerAddresses(["100.64.0.7/32", "100.64.0.7/32"]), { overlay: "100.64.0.7", routes: [], exits: [] });
});
test("an exit-only peer has no subnets and repeated defaults are counted once", () => {
  assert.deepEqual(peerAddresses(["100.64.0.7/32", "0.0.0.0/0", "::/0", "0.0.0.0/0"]), {
    overlay: "100.64.0.7", routes: [], exits: ["0.0.0.0/0", "::/0"],
  });
});
