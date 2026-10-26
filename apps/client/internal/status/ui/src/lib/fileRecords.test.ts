import assert from "node:assert/strict";
import { test } from "node:test";
import { fileRecords, fileRecordMatches, fileRequests, fileJobState, fileJobSummary } from "./fileRecords.ts";

test("outgoing batches retain every source name and show aggregate bytes after advancing", () => {
  const sources = [{ id: "a", name: "first.jpg", size: 100 }, { id: "b", name: "same.jpg", size: 200 }, { id: "c", name: "same.jpg", size: 300 }];
  const batch = { ...job("batch", "sending"), sources: ["a", "b", "c"] };
  batch.progress = { index: 2, count: 3, transfer: { ...batch.progress.transfer, name: "same.jpg", size: 300, offset: 50 } };
  assert.deepEqual(fileJobSummary(batch, sources).files.map(file => file.id), ["a", "b", "c"]);
  assert.equal(fileJobSummary(batch, sources).offset, 350);
  assert.equal(fileJobSummary(batch, sources).size, 600);
  batch.state = "paused";
  assert.equal(fileJobSummary(batch, sources).offset, 350);
  batch.state = "completed";
  assert.equal(fileJobSummary(batch, sources).offset, 600);
  // Sources may be polled in a different order; file order follows the journal.
  assert.deepEqual(fileJobSummary(batch, sources.reverse()).files.map(file => file.id), ["a", "b", "c"]);
});

test("single-file, zero-byte and legacy missing-source jobs remain readable", () => {
  const legacy = job("legacy", "completed");
  assert.equal(fileJobSummary(legacy, []).files.length, 1);
  const empty = { ...job("empty", "completed"), sources: ["empty"] };
  assert.deepEqual(fileJobSummary(empty, [{ id: "empty", name: "empty.txt", size: 0 }]), { files: [{ id: "empty", name: "empty.txt", size: 0 }], size: 0, offset: 0 });
});

const received = (id: string, state: string, device = "mac", batch = "batch", count = 2) => ({ device_key: device, ip: "100.64.0.18", transfer: { id, state, batch, batch_count: count, name: id, offset: 0, size: 1024 } });
const job = (id: string, state: string, cancel_pending = false) => ({ id, state, cancel_pending, peer_ip: "100.64.0.18", progress: { index: 0, count: 1, transfer: { id: "t-"+id, state, name: id, batch: "b", batch_count: 1, size: 1024, offset: 0 } } });

test("combined records keep identity and order when polling arrays and progress change", () => {
  const data = { jobs: [job("b", "sending"), job("a", "paused")], received: [received("z", "receiving"), received("c", "completed")] };
  const before = fileRecords(data).map(row => row.key);
  data.jobs.reverse(); data.received.reverse();
  data.jobs[0].state = "completed"; data.jobs[1].progress.transfer.offset = 1000;
  assert.deepEqual(fileRecords(data).map(row => row.key), before);
  assert.equal(new Set(before).size, 4);
});

test("active includes paused and cancellation-pending jobs; completed excludes them", () => {
  const rows = fileRecords({ jobs: [job("pause", "paused"), job("cancel", "cancelled", true), job("done", "completed"), job("old", "cancelled")], received: [received("verify", "verifying"), received("done", "completed"), received("wait", "waiting")] });
  assert.equal(rows.filter(row => fileRecordMatches(row,"active")).length, 3);
  assert.equal(rows.filter(row => fileRecordMatches(row,"completed")).length, 2);
  assert.equal(rows.filter(row => fileRecordMatches(row,"waiting")).length, 0);
  assert.equal(rows.length, 6); // Waiting stays in the batch confirmation area.
});

test("batch confirmation does not merge devices or enable a partially arrived batch", () => {
  const rows = [received("a", "waiting"), received("b", "waiting", "linux"), received("c", "completed", "done")];
  const requests = fileRequests(rows);
  assert.equal(requests.length, 2);
  assert.ok(requests.every(request => !request.complete));
  rows.push(received("d", "waiting"));
  const mac = fileRequests(rows).find(request => request.key === "mac/batch")!;
  assert.equal(mac.complete, true);
  assert.deepEqual(mac.waiting.map(row=>row.transfer.id), ["a","d"]);
});

test("local pause, recipient pause, interruption and peer termination have distinct meanings", () => {
  assert.equal(fileJobState(job("local", "paused")), "paused");
  assert.equal(fileJobState({ ...job("retry", "paused"), error: "network timeout" }), "interrupted");
  const sending = job("peer", "sending");
  sending.progress.transfer.state = "paused";
  assert.equal(fileJobState(sending), "receiver_paused");
  assert.equal(fileJobState({ ...job("cancel", "cancelled", true), stop_reason: "receiver_cancelled" }), "receiver_cancelled");
  assert.equal(fileJobState({ ...job("reject", "cancelled"), stop_reason: "receiver_rejected" }), "receiver_rejected");
  for (const state of ["paused", "waiting_sender"]) {
    assert.equal(fileRecordMatches({ key: state, direction: "incoming", received: received("file", state) }, "active"), true);
  }
});


test("records and requests sort newest first without reacting to progress", () => {
  const oldJob = { ...job("a", "sending"), created_unix_ms: 100 };
  const newJob = { ...job("z", "paused"), created_unix_ms: 300 };
  const incoming = received("middle", "completed");
  const datedIncoming = { ...incoming, transfer: { ...incoming.transfer, created_unix_ms: 200 } };
  const input = { jobs: [oldJob, newJob], received: [datedIncoming] };
  assert.deepEqual(fileRecords(input).map(row => row.key), ["out/z", "in/mac/middle", "out/a"]);
  oldJob.progress.transfer.offset = 999;
  assert.equal(fileRecords(input)[0].key, "out/z");
});
