// Run with: node --test src/lib/cidr.test.ts   (node >= 22 strips the types)
import { test } from "node:test";
import assert from "node:assert/strict";
import { exitStanding, isExitRoute, routeStanding, type RouteReport } from "./cidr.ts";

const report = (over: Partial<RouteReport> = {}): RouteReport => ({
  up: true,
  netmapSeen: true,
  published: [],
  ...over,
});

// THE REPORTED BUG: a subnet is saved, the coordinator has answered, and it is
// not routing it here because no admin approved it. The page used to show the
// row exactly as it shows a working one.
test("a saved route the coordinator does not publish is pending", () => {
  assert.equal(routeStanding("192.168.1.0/24", ["192.168.1.0/24"], report()), "pending");
});

test("a saved route the coordinator publishes is published", () => {
  const r = report({ published: ["192.168.1.0/24"] });
  assert.equal(routeStanding("192.168.1.0/24", ["192.168.1.0/24"], r), "published");
});

// "Pending" says an admin has not acted. Before the coordinator has answered
// that is not known, and after every save the session restarts — so a warning
// that fires on an empty list alone would flash each time.
test("pending is not claimed before the coordinator has answered", () => {
  const saved = ["192.168.1.0/24"];
  assert.equal(routeStanding(saved[0], saved, report({ netmapSeen: false })), "checking");
  assert.equal(routeStanding(saved[0], saved, report({ up: false })), "offline");
  // A stale published list from before the mesh stopped must not read as live.
  assert.equal(
    routeStanding(saved[0], saved, report({ up: false, published: saved })),
    "offline",
  );
});

test("a row that is only in the form is unsaved, whatever the coordinator says", () => {
  const r = report({ published: ["10.9.0.0/24"] });
  assert.equal(routeStanding("10.9.0.0/24", ["192.168.1.0/24"], r), "unsaved");
});

// The daemon stores what a person typed after masking it, and reports published
// routes masked as well; a config file may hold the unmasked spelling.
test("routes are compared by network, not by spelling", () => {
  const r = report({ published: ["192.168.1.0/24", "192.168.7.22/32"] });
  assert.equal(routeStanding("192.168.1.5/24", ["192.168.1.5/24"], r), "published");
  assert.equal(routeStanding("192.168.7.22/32", ["192.168.7.22/32"], r), "published");
});

test("the exit-device offer follows the default route", () => {
  assert.equal(exitStanding(true, report()), "pending");
  assert.equal(exitStanding(true, report({ published: ["0.0.0.0/0"] })), "published");
  assert.equal(exitStanding(true, report({ published: ["::/0"] })), "published");
  // An approved subnet says nothing about the exit offer.
  assert.equal(exitStanding(true, report({ published: ["192.168.1.0/24"] })), "pending");
  assert.equal(exitStanding(false, report({ published: ["0.0.0.0/0"] })), "unsaved");
  assert.equal(exitStanding(true, report({ netmapSeen: false })), "checking");
  assert.equal(exitStanding(true, report({ up: false })), "offline");
});

test("isExitRoute matches default routes only", () => {
  assert.equal(isExitRoute("0.0.0.0/0"), true);
  assert.equal(isExitRoute("::/0"), true);
  assert.equal(isExitRoute("10.0.0.0/8"), false);
  assert.equal(isExitRoute("192.168.1.0/24"), false);
});
