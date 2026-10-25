// Node addresses occupy 100.64.0.0/11; aliases occupy 100.96.0.0/11.
// WireGuard can return allowed prefixes in any order, including target /32s.
export function peerAddresses(allowed: string[] = []): { overlay: string; routes: string[]; exits: string[] } {
  const overlayPrefix = allowed.find((cidr) => {
    const match = /^(100)\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/32$/.exec(cidr);
    return !!match && Number(match[2]) >= 64 && Number(match[2]) <= 95 &&
      Number(match[3]) <= 255 && Number(match[4]) <= 255;
  });
  return {
    overlay: overlayPrefix?.replace(/\/32$/, "") || "",
    routes: [...new Set(allowed.filter((cidr) => cidr !== overlayPrefix && cidr !== "0.0.0.0/0" && cidr !== "::/0"))],
    exits: [...new Set(allowed.filter((cidr) => cidr === "0.0.0.0/0" || cidr === "::/0"))],
  };
}
