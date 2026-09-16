// Run with: node --test src/lib/updatePoll.test.ts   (node >= 22 strips the types)
import { test } from "node:test";
import assert from "node:assert/strict";
import { updatePollInterval, UPDATE_POLL_ACTIVE_MS, UPDATE_POLL_IDLE_MS } from "./updatePoll.ts";

// THE BUG. The "check now" button's spinner is bound to `state === "checking"`,
// so a stale snapshot saying "checking" spins for one whole polling interval
// after the check is over — the daemon answered in 200ms and the button ran for
// the rest of the minute. Whatever puts that stale value in the cache (a GET
// that was in flight when the check finished, another tab, the periodic tick),
// the page's own recovery time is the polling interval.
test("while something is running, ask again in seconds — not in a minute", () => {
  assert.equal(updatePollInterval({ state: "checking" }), UPDATE_POLL_ACTIVE_MS);
  assert.equal(updatePollInterval({ state: "updating" }), UPDATE_POLL_ACTIVE_MS);
  assert.ok(UPDATE_POLL_ACTIVE_MS < UPDATE_POLL_IDLE_MS);
});

// The other half: idle must NOT poll fast. This query exists to re-read a
// six-hourly check; one request every two seconds forever would be a busy loop
// against the daemon for no information.
test("at rest it stays at the slow interval", () => {
  assert.equal(updatePollInterval({ state: "idle" }), UPDATE_POLL_IDLE_MS);
  assert.equal(updatePollInterval({ state: "failed" }), UPDATE_POLL_IDLE_MS);
  assert.equal(updatePollInterval(undefined), UPDATE_POLL_IDLE_MS);
  assert.equal(updatePollInterval(null), UPDATE_POLL_IDLE_MS);
  assert.equal(updatePollInterval({}), UPDATE_POLL_IDLE_MS);
});

// A newer daemon's state must degrade to "at rest". Treating an unknown value
// as busy would leave an older console polling every two seconds forever, with
// nothing that could ever clear it.
test("an unrecognised state from a newer daemon is treated as at rest", () => {
  assert.equal(updatePollInterval({ state: "rolling-back" }), UPDATE_POLL_IDLE_MS);
});
