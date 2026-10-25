import catalogJSON from "./businessErrors.json" with { type: "json" };

type Args = Record<string, string>;
type Translate = (key: string, options: { defaultValue: string }) => string;
interface Rule { key: string; pattern: string; args?: Record<string, number>; constants?: Args }
interface Catalog { messages: Record<string, string>; rules: Rule[]; codes: Record<string, string>; arguments: Record<string, { pattern?: string; values?: string[] }> }
const catalog = catalogJSON as unknown as Catalog;
const rules = catalog.rules.map((rule) => ({ ...rule, re: new RegExp(rule.pattern, "i") }));
const own = (object: object, key: string) => Object.prototype.hasOwnProperty.call(object, key);
const resources: Record<string, string> = {
  organization: "organization", device: "device", tunnel: "tunnel", order: "order",
  subscription: "subscription", invoice: "invoice", certificate: "certificate", domain: "domain",
  task: "task", session: "session", "API key": "apiKey", "support ticket": "supportTicket",
  account: "account", plan: "plan", capture: "capture", "TCP/UDP tunnels": "tcpUdpTunnels",
  "reserved subdomains": "reservedSubdomains", resources: "resources",
};

export function matchBusiness(raw: unknown, code?: unknown): { key: string; args: Args } | null {
  let msg = typeof raw === "string" ? raw.trim().replace(/^calabi: code=\d+\s+/, "") : "";
  while (msg.includes("rpc error: code = ")) {
    const match = /rpc error: code = (\w+) desc = ([\s\S]*)/.exec(msg);
    if (!match || /^(Internal|Unknown|DataLoss|Unavailable|DeadlineExceeded)$/.test(match[1])) return null;
    msg = match[2];
  }
  if (typeof code === "string" && own(catalog.codes, code)) return { key: `business.${catalog.codes[code]}`, args: {} };
  for (const rule of rules) {
    const match = rule.re.exec(msg);
    if (!match) continue;
    const args = { ...rule.constants };
    for (const [name, index] of Object.entries(rule.args || {})) args[name] = match[index];
    return { key: `business.${rule.key}`, args };
  }
  return null;
}

export function renderBusiness(key: unknown, values?: unknown, t?: Translate): string | null {
  if (typeof key !== "string" || !key.startsWith("business.")) return null;
  const name = key.slice("business.".length);
  if (!own(catalog.messages, name)) return null;
  const args: Args = {};
  if (values && typeof values === "object" && !Array.isArray(values)) {
    for (const [k, v] of Object.entries(values)) if (typeof v === "string" || typeof v === "number") args[k] = String(v);
  }
  const template = catalog.messages[name];
  const slots = [...template.matchAll(/\{\{([a-zA-Z]+)\}\}/g)].map((match) => match[1]);
  if (slots.some((slot) => !own(args, slot))) return null;
  if (slots.some((slot) => {
    const rule = catalog.arguments[slot];
    if (!rule) return true;
    return rule.pattern ? !new RegExp(rule.pattern, "u").test(args[slot]) : !rule.values?.includes(args[slot]);
  })) return null;
  if (own(args, "resource") && own(resources, args.resource) && t) {
    args.resource = t(`apiErrorResources.${resources[args.resource]}`, { defaultValue: args.resource });
  }
  const text = t ? t(`apiBusinessErrors.${name}`, { defaultValue: template, ...args }) : template;
  return text.replace(/\{\{([a-zA-Z]+)\}\}/g, (_, slot: string) => args[slot] ?? "");
}

export function businessHints(body: Record<string, unknown>, t?: Translate): string[] {
  // Operator-only instructions live in the admin bundle, outside this shared
  // catalog. Older clients still receive the readable English hint.
  if (typeof body.hint_key === "string" && /^operator\.[a-zA-Z]+$/.test(body.hint_key) && typeof body.hint === "string") {
    return [t ? t(`operatorHints.${body.hint_key.slice("operator.".length)}`, { defaultValue: body.hint }) : body.hint];
  }
  if (Array.isArray(body.hints)) {
    return body.hints.flatMap((hint: unknown) => {
      if (!hint || typeof hint !== "object") return [];
      const h = hint as Record<string, unknown>;
      const rendered = renderBusiness(h.key, h.args, t);
      return rendered ? [rendered] : [];
    });
  }
  if (typeof body.hint !== "string" || !body.hint) return [];
  const known = matchBusiness(body.hint);
  if (!known) return [body.hint];
  const result = [renderBusiness(known.key, known.args, t) || body.hint];
  // Older gateways appended completion counts to their English refusal.
  const devices = /(\d+) mesh device\(s\) disabled/.exec(body.hint)?.[1] || "0";
  const tunnels = /(\d+) tunnel\(s\) disabled/.exec(body.hint)?.[1] || "0";
  const keys = /(\d+) API key\(s\) revoked/.exec(body.hint)?.[1] || "0";
  if (devices !== "0" || tunnels !== "0" || keys !== "0") {
    result.push(renderBusiness("business.offboardCompleted", { devices, tunnels, keys }, t)!);
  }
  return result;
}
