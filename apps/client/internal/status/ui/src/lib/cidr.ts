// cidr.ts — client-side route validation for the routing editors.
//
// The daemon validates too (statusapi runs mesh.ParseRoute), but a round-trip is
// a poor way to learn you typed 192.168.1.0/33: the whole save fails, including
// the parts that were fine. Catching it at the keystroke keeps a typo from
// costing the rest of the form. This file mirrors mesh/routespec.go — keep the
// two in step.
//
// Three rules, all of them the daemon's:
//
//  1. A bare address is a host route: "192.168.1.22" means 192.168.1.22/32.
//     Someone publishing one machine thinks of it as an address, and the "/32"
//     is ceremony. formatRoute renders it back the short way.
//  2. IPv4 is normalized to its network address (192.168.1.5/24 → 192.168.1.0/24)
//     because the daemon masks it anyway — a value that silently changes after
//     saving reads like the UI lost the edit. IPv6 is validated but NOT masked:
//     re-implementing v6 masking in the browser buys nothing (the daemon does it)
//     and getting it subtly wrong would cost something.
//  3. An IPv4 route wider than /24 is refused, with the containing /24 offered as
//     the thing to type instead. See ROUTE_MIN_BITS_V4.

/**
 * ROUTE_MIN_BITS_V4 is the widest IPv4 route that may be published.
 *
 * Every published route gets a NAT alias, and an alias costs its own size in
 * pool addresses: a /24 costs 256 — exactly the default budget — while a /16
 * costs 65,536, so a /16 could never be granted one. It used to be accepted and
 * then silently published under its real address, i.e. straight back into the
 * collision aliases exist to prevent.
 */
export const ROUTE_MIN_BITS_V4 = 24;

/** What parseRoute decided: a storable CIDR, or why it refused. */
export type RouteParse =
  | { ok: true; cidr: string }
  | { ok: false; reason: "invalid" }
  | { ok: false; reason: "tooBroad"; suggest: string };

/**
 * parseRoute validates one route as a person writes it.
 *
 * enforceWidth is the publish-side rule and defaults to on. The consumer-side
 * exclusion list passes false: refusing a whole /16 from this machine's routing
 * table is cheap and reasonable, and costs the shared alias pool nothing —
 * applying the publish limit there would remove a capability for no reason.
 */
export function parseRoute(input: string, enforceWidth = true): RouteParse {
  const s = input.trim();
  if (!s) return { ok: false, reason: "invalid" };

  const slash = s.lastIndexOf("/");
  // No mask: a bare address is a host route.
  if (slash < 0) {
    const bits = s.includes(":") ? 128 : 32;
    const norm = normalizeCidr(`${s}/${bits}`);
    return norm ? { ok: true, cidr: norm } : { ok: false, reason: "invalid" };
  }

  const norm = normalizeCidr(s);
  if (!norm) return { ok: false, reason: "invalid" };
  if (enforceWidth && !norm.includes(":")) {
    const bits = Number(norm.slice(norm.lastIndexOf("/") + 1));
    if (bits < ROUTE_MIN_BITS_V4) {
      // Name a concrete alternative: "too broad" on its own leaves the reader
      // guessing at the limit.
      const suggest = normalizeCidr(
        `${norm.slice(0, norm.lastIndexOf("/"))}/${ROUTE_MIN_BITS_V4}`,
      );
      return { ok: false, reason: "tooBroad", suggest: suggest ?? "" };
    }
  }
  return { ok: true, cidr: norm };
}

/**
 * formatRoute renders a stored route the way parseRoute accepts it: a host route
 * as a bare address, everything else as CIDR. What the console shows is then
 * what a person would type.
 */
export function formatRoute(cidr: string): string {
  const slash = cidr.lastIndexOf("/");
  if (slash < 0) return cidr;
  const host = cidr.slice(0, slash);
  const bits = cidr.slice(slash + 1);
  if ((host.includes(":") && bits === "128") || (!host.includes(":") && bits === "32")) {
    return host;
  }
  return cidr;
}

/** normalizeCidr returns the storable form of a CIDR, or null if it isn't one. */
export function normalizeCidr(input: string): string | null {
  const s = input.trim();
  const slash = s.lastIndexOf("/");
  if (slash <= 0 || slash === s.length - 1) return null;
  const host = s.slice(0, slash);
  const bitsRaw = s.slice(slash + 1);
  if (!/^\d{1,3}$/.test(bitsRaw)) return null;
  const bits = Number(bitsRaw);

  if (host.includes(":")) {
    if (bits > 128) return null;
    // The URL parser is the browser's own IPv6 literal validator — stricter and
    // better tested than anything worth hand-rolling here.
    try {
      // eslint-disable-next-line no-new
      new URL(`http://[${host}]/`);
    } catch {
      return null;
    }
    return `${host}/${bits}`;
  }

  if (bits > 32) return null;
  const parts = host.split(".");
  if (parts.length !== 4) return null;
  const octets: number[] = [];
  for (const p of parts) {
    // Reject "01" and "1e2": a leading zero means octal to some parsers and
    // decimal to others, and that ambiguity has burned real firewalls.
    if (!/^(0|[1-9]\d{0,2})$/.test(p)) return null;
    const n = Number(p);
    if (n > 255) return null;
    octets.push(n);
  }
  const masked = octets.map((o, i) => {
    const take = Math.min(8, Math.max(0, bits - i * 8));
    return take === 0 ? 0 : o & ((0xff << (8 - take)) & 0xff);
  });
  return `${masked.join(".")}/${bits}`;
}
