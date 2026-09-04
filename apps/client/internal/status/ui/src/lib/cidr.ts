// cidr.ts — client-side CIDR validation for the routing editors.
//
// The daemon validates too (statusapi rejects a bad prefix), but a round-trip is
// a poor way to learn you typed 192.168.1.0/33: the whole save fails, including
// the parts that were fine. Catching it at the keystroke keeps a typo from
// costing the rest of the form.
//
// IPv4 is normalized to its network address (192.168.1.5/24 → 192.168.1.0/24)
// because the daemon masks it anyway — a value that silently changes after
// saving reads like the UI lost the edit. IPv6 is validated but NOT masked:
// re-implementing v6 masking in the browser buys nothing (the daemon does it)
// and getting it subtly wrong would cost something.

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
