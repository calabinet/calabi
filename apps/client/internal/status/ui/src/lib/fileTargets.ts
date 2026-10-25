import type { FilePeer } from "../api/files";
import type { MeshPeer } from "../api/types";
import { peerAddresses } from "./peerAddresses.ts";

export type FileTarget = { key: string; name: string; ip: string; status: "ready" | "receivingOff" | "notReady" };

// Device identity comes from the mesh list; a live file grant only authorizes
// sending to that same key/address. Missing grants must not hide the device.
export function fileTargets(devices: MeshPeer[], grants: FilePeer[], now = Date.now() / 1000): FileTarget[] {
  const live = grants.filter(p => p.expires_unix > now);
  const targets = new Map<string, FileTarget>();
  for (const device of devices) {
    targets.set(device.public_key, { key: device.public_key, name: device.name || "", ip: peerAddresses(device.allowed_ips).overlay, status: "notReady" });
  }
  for (const peer of live) {
    const key = peer.grant.device_key;
    const target = targets.get(key);
    // Never send to a newly assigned address using an old grant.
    if (target && target.ip !== peer.grant.peer.IP) continue;
    targets.set(key, { key, name: target?.name || peer.name, ip: peer.grant.peer.IP, status: peer.grant.receiving ? "ready" : "receivingOff" });
  }
  return [...targets.values()];
}
