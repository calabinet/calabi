import assert from "node:assert/strict";
import { test } from "node:test";
import { QueryClient, QueryObserver, focusManager } from "@tanstack/react-query";
import { displayedPeerPresence, isPresenceCurrent, peerPresence, presenceQueryOptions } from "./peerPresence.ts";

test("presence uses the exact device address and preserves explicit offline vs unknown", () => {
  const nodes = [{overlay:"100.64.0.18",online:true},{overlay:"100.64.0.19",online:false},{overlay:"100.96.0.1",online:true}];
  assert.equal(peerPresence(["100.96.0.1/32","100.64.0.19/32"],nodes),"offline");
  assert.equal(peerPresence(["100.64.0.18/32"],nodes),"online"); // Includes an idle or never-handshaken device.
  assert.equal(peerPresence(["100.96.0.1/32"],nodes),"unknown");
  assert.equal(peerPresence(["100.64.0.18/32"],undefined),"unknown");
  assert.equal(peerPresence(["100.64.0.18/32"],[{overlay:"100.64.0.18"}]),"unknown");
});

test("reopening immediately fetches presence and omits expired badges until it completes", async (t) => {
  focusManager.setFocused(false);
  const client = new QueryClient({ defaultOptions: { queries: { refetchOnWindowFocus: false, retry: false } } });
  client.mount();
  const key = ["mesh-org-nodes", 1, 1];
  const nodes = [{ overlay: "100.64.0.18", online: true }];
  client.setQueryData(key, { items: nodes }, { updatedAt: Date.now() - 20_000 });
  let finish: ((value: { items: typeof nodes }) => void) | undefined;
  let requests = 0;
  const observer = new QueryObserver(client, {
    queryKey: key,
    queryFn: () => { requests++; return new Promise<{ items: typeof nodes }>(resolve => { finish = resolve; }); },
    ...presenceQueryOptions,
    refetchOnMount: false,
    refetchInterval: false, // Reopening must not wait for a polling tick.
  });
  const unsubscribe = observer.subscribe(() => {});
  t.after(() => { unsubscribe(); observer.destroy(); client.unmount(); client.clear(); focusManager.setFocused(undefined); });
  assert.equal(requests, 0);
  focusManager.setFocused(true);
  await new Promise<void>(resolve => setImmediate(resolve));
  assert.equal(requests, 1);
  const fetching = observer.getCurrentResult();
  assert.equal(fetching.isFetching, true);
  assert.equal(displayedPeerPresence(["100.64.0.18/32"], nodes, true, fetching), null);
  assert.equal(displayedPeerPresence(["100.64.0.18/32"], nodes, false, fetching), "unknown");
  finish!({ items: nodes });
  await observer.refetch({ cancelRefetch: false });
  assert.equal(displayedPeerPresence(["100.64.0.18/32"], nodes, true, observer.getCurrentResult()), "online");
});

test("refreshing keeps valid badges; a failed fetch with no valid snapshot shows unknown", () => {
  const nodes = [{ overlay: "100.64.0.18", online: false }];
  const fresh = { data: { items: nodes }, dataUpdatedAt: 10_000, isFetching: true };
  assert.equal(displayedPeerPresence(["100.64.0.18/32"], nodes, true, fresh, 11_000), "offline");
  const expired = { ...fresh, dataUpdatedAt: 1_000 };
  assert.equal(displayedPeerPresence(["100.64.0.18/32"], nodes, true, expired, 20_000), null);
  assert.equal(displayedPeerPresence(["100.64.0.18/32"], nodes, true, { ...expired, isFetching: false }, 20_000), "unknown");
  assert.equal(displayedPeerPresence(["100.64.0.18/32"], undefined, true, { dataUpdatedAt: 0, isFetching: true }), null);
});

test("a failed background poll preserves fresh presence until expiry, then recovers", async (t) => {
  const client = new QueryClient();
  let fail = false;
  const nodes = [{ overlay: "100.64.0.18", online: true }, { overlay: "100.64.0.19", online: false }];
  const observer = new QueryObserver(client, {
    queryKey: ["mesh-org-nodes", 1, 1],
    enabled: false,
    retry: false,
    queryFn: async () => {
      if (fail) throw new Error("transient upstream failure");
      return { items: nodes };
    },
  });
  t.after(() => { observer.destroy(); client.clear(); });
  assert.equal(isPresenceCurrent(true, observer.getCurrentResult()), false);
  const first = await observer.refetch();
  assert.equal(isPresenceCurrent(true, first, first.dataUpdatedAt), true);

  fail = true;
  const failed = await observer.refetch();
  assert.equal(failed.isSuccess, false); // This used to hide the whole table's presence.
  assert.equal(failed.dataUpdatedAt, first.dataUpdatedAt);
  const visibleNodes = isPresenceCurrent(true, failed, first.dataUpdatedAt + 5_000) ? failed.data?.items : undefined;
  assert.equal(peerPresence(["100.64.0.18/32"], visibleNodes), "online");
  assert.equal(peerPresence(["100.64.0.19/32"], visibleNodes), "offline");
  assert.equal(isPresenceCurrent(true, failed, first.dataUpdatedAt + 14_999), true);
  assert.equal(isPresenceCurrent(true, failed, first.dataUpdatedAt + 15_000), false);
  assert.equal(isPresenceCurrent(false, failed, first.dataUpdatedAt + 5_000), false); // Mesh down or organization mismatch.

  fail = false;
  const recovered = await observer.refetch();
  assert.equal(recovered.isSuccess, true);
  assert.equal(isPresenceCurrent(true, recovered, recovered.dataUpdatedAt), true);
});
