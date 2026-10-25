import assert from "node:assert/strict";
import { test } from "node:test";
import { fileTargets } from "./fileTargets.ts";

const device = (key: string, ip: string) => ({ public_key: key, name: key, allowed_ips: [`${ip}/32`], last_handshake_sec: 0, rx_bytes: 0, tx_bytes: 0 });
const grant = (key: string, ip: string, receiving = true, expires = 200) => ({ name: key, expires_unix: expires, grant: { device_key: key, peer: { IP: ip, Fingerprint: "pin" }, receiving } });

test("clicked device remains visible while its file agent is absent or expires", () => {
  const peers = [device("linux", "100.64.0.16")];
  assert.deepEqual(fileTargets(peers, [], 100), [{ key: "linux", name: "linux", ip: "100.64.0.16", status: "notReady" }]);
  assert.equal(fileTargets(peers, [grant("linux", "100.64.0.16", true, 99)], 100)[0].status, "notReady");
});
test("same selected device becomes sendable when its receiver starts", () => {
  const peers = [device("linux", "100.64.0.16")];
  assert.equal(fileTargets(peers, [grant("linux", "100.64.0.16", false)], 100)[0].status, "receivingOff");
  assert.equal(fileTargets(peers, [grant("linux", "100.64.0.16")], 100)[0].status, "ready");
});
test("a reassigned IP cannot silently replace the selected device", () => {
  const targets = fileTargets([device("new", "100.64.0.16"), device("old", "100.64.0.17")], [grant("old", "100.64.0.16")], 100);
  assert.equal(targets.find(p => p.key === "old")?.status, "notReady");
  assert.equal(targets.find(p => p.key === "new")?.status, "notReady");
});
test("authenticated grants can populate the centre before mesh polling finishes", () => {
  assert.equal(fileTargets([], [grant("linux", "100.64.0.16")], 100)[0].key, "linux");
});
