// What an endpoint type is called on screen, and whether TLS can be offered.
//
// `sni` is the wire type of a TLS (passthrough) endpoint: the edge routes by the
// TLS server name and never decrypts, and the user's own service holds the
// certificate. The product calls it TLS; the API, the database and the CLI keep
// `sni`.

export function typeLabel(type: string | undefined): string {
  const k = (type || "").toLowerCase();
  return k === "sni" ? "TLS" : k.toUpperCase();
}

// Byte-passthrough types, which have no L7 and so can only ever be guarded by an
// address list (and slowed by a rate limit). Mirrors store.IsBarePort in
// tunnel-svc, which is the one that decides — this copy exists so the create
// form asks for the right thing before submitting and the security drawer
// offers only what the edge applies, not so the client can decide anything.
export function isBarePortType(tunnelType: string | undefined): boolean {
  switch ((tunnelType || "").trim().toLowerCase()) {
    case "tcp":
    case "udp":
    case "sni":
      return true;
    default:
      return false;
  }
}

export type TlsOffer = "ok" | "needsOwnNode" | "needsUpgrade" | "needsDomain" | "needsHttpsPort";

// clientTlsOffer says whether this daemon's create page can offer TLS, or which
// one thing is missing.
//
// On the platform the endpoint lands on the node the daemon is connected to, so
// that node has to be the org's own (onOwnEdge) and report it takes TLS
// endpoints (edgeTakesTls — tls_passthrough on its directory row; an older
// build does not), and there has to be a verified domain it serves. bff-console
// refuses the same cases at create; this says which before anyone clicks.
//
// Standalone: the node is the user's own and passes TLS through on its HTTPS
// port, so the port is all that can be missing. Never a plan tier.
export function clientTlsOffer(o: {
  standalone: boolean;
  httpsPort?: number;
  onOwnEdge: boolean;
  edgeTakesTls: boolean;
  parentDomains: number;
}): TlsOffer {
  if (o.standalone) return (o.httpsPort ?? 0) > 0 ? "ok" : "needsHttpsPort";
  if (!o.onOwnEdge) return "needsOwnNode";
  if (!o.edgeTakesTls) return "needsUpgrade";
  if (o.parentDomains === 0) return "needsDomain";
  return "ok";
}
