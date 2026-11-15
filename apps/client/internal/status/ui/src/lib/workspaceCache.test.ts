import assert from "node:assert/strict";
import { test } from "node:test";
import { emptyWorkspaceCache, workspaceCache } from "./workspaceCache.ts";

test("closing sessions while another remains releases previews and ignores late frames", () => {
  let cache = workspaceCache(emptyWorkspaceCache(), { type: "sessions", ids: ["keep"] });
  cache = workspaceCache(cache, { type: "preview", id: "keep", text: "retained" });
  for (let i = 0; i < 1000; i++) {
    const id = `session-${i}`;
    cache = workspaceCache(cache, { type: "sessions", ids: ["keep", id] });
    cache = workspaceCache(cache, { type: "preview", id, text: "data:image/png;base64,frame" });
    cache = workspaceCache(cache, { type: "files", id, open: true });
    cache = workspaceCache(cache, { type: "sessions", ids: ["keep"] });
    const closed = cache;
    cache = workspaceCache(cache, { type: "preview", id, text: "late final frame" });
    assert.equal(cache, closed);
    assert.deepEqual(cache.previews, { keep: "retained" });
    assert.deepEqual(cache.files, {});
  }
  cache = workspaceCache(cache, { type: "sessions", ids: [] });
  assert.equal(cache.ids.size, 0);
  assert.deepEqual(cache.previews, {});
});

test("unchanged polling preserves cache identity and open sessions retain their previews", () => {
  let cache = workspaceCache(emptyWorkspaceCache(), { type: "sessions", ids: ["a", "b"] });
  cache = workspaceCache(cache, { type: "preview", id: "b", text: "frame" });
  assert.equal(workspaceCache(cache, { type: "sessions", ids: ["b", "a"] }), cache);
  assert.equal(workspaceCache(cache, { type: "preview", id: "b", text: "frame" }), cache);
  cache = workspaceCache(cache, { type: "sessions", ids: ["b"] });
  assert.deepEqual(cache.previews, { b: "frame" });
});
