// Adds separate, loopback-only routes for diagnostics and Claude Desktop.
function main(config) {
  if (!config || typeof config !== "object") return config;
  const routes = [
    { name: "claude-guard-probe", port: 17897, proxy: "Guard-Probe" },
    { name: "claude-guard-app", port: 17898, proxy: "Guard-Claude" },
  ].map(route => ({ ...route, type: "http", listen: "127.0.0.1", users: [] }));
  const groups = Array.isArray(config["proxy-groups"]) ? config["proxy-groups"] : [];
  const listeners = Array.isArray(config.listeners) ? config.listeners : [];
  const replacedGroups = new Set();
  const replacedListeners = new Set();
  const ports = ["mixed-port", "port", "socks-port", "redir-port", "tproxy-port"];
  for (const route of routes) {
    if (ports.some(key => Number(config[key]) === route.port)) throw new Error(`端口 ${route.port} 已被使用`);
    const existingGroups = groups.filter(group => group?.name === route.proxy);
    const existingListeners = listeners.filter(listener => listener?.name === route.name || Number(listener?.port) === route.port);
    if (!(existingGroups.length || existingListeners.length)) continue;
    const [group] = existingGroups;
    const [listener] = existingListeners;
    const ownListener = existingListeners.length === 1 && Object.keys(route).every(key =>
      key === "users" ? Array.isArray(listener.users) && listener.users.length === 0 : listener[key] === route[key]);
    const ownGroup = existingGroups.length === 1 && group.type === "select" &&
      group["default-selected"] === "REJECT" && group["empty-fallback"] === "REJECT";
    if (!(ownListener && ownGroup)) throw new Error(`${route.proxy} 或端口 ${route.port} 已被使用`);
    replacedGroups.add(group);
    replacedListeners.add(listener);
  }

  const nodes = Array.isArray(config.proxies) ? config.proxies : [];
  const taken = new Set(groups.map(group => group?.name));
  const counts = new Map();
  for (const node of nodes) {
    if (typeof node?.name === "string") counts.set(node.name, (counts.get(node.name) || 0) + 1);
  }
  if (routes.some(route => counts.has(route.proxy)) || counts.has("REJECT") || taken.has("REJECT")) {
    throw new Error("Guard-Probe、Guard-Claude 或 REJECT 名称已被订阅使用");
  }
  const relayTypes = new Set([
    "anytls", "http", "hysteria", "hysteria2", "mieru", "shadowquic", "snell", "socks5", "ss", "ssr",
    "ssh", "trojan", "trusttunnel", "tuic", "vless", "vmess", "wireguard",
  ]);
  const reserved = /^(?:global|direct|compatible|pass|reject(?:-?drop)?|dns|rematch|guard-?(?:probe|claude))$/i;
  const candidates = nodes.filter(node => {
    if (typeof node?.name !== "string" || !node.name.trim() || reserved.test(node.name.trim())) return false;
    return counts.get(node.name) === 1 && !taken.has(node.name) && relayTypes.has(String(node.type).trim().toLowerCase());
  }).map(node => node.name);

  const ownGroups = routes.map(route => ({
    name: route.proxy, type: "select", "empty-fallback": "REJECT", "default-selected": "REJECT", proxies: ["REJECT", ...candidates],
  }));
  config["proxy-groups"] = [...ownGroups, ...groups.filter(group => !replacedGroups.has(group))];
  config.listeners = [...listeners.filter(listener => !replacedListeners.has(listener)), ...routes];
  return config;
}
