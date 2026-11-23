/* Clash Verge Rev 全局扩展脚本：保留订阅分流与私有 DNS，添加本机隔离的 Guard-Probe 体检入口。 */

function main(config, profileName) {
  if (!config || typeof config !== "object") {
    return config;
  }

  var PROBE_GROUP = "Guard-Probe";
  var PROBE_INBOUND = "claude-guard-probe";
  var PROBE_PORT = 17897;
  var RELAY_TYPES = {
    anytls: true, http: true, hysteria: true, hysteria2: true, mieru: true,
    shadowquic: true, snell: true, socks5: true, ss: true, ssr: true, ssh: true,
    trojan: true, trusttunnel: true, tuic: true, vless: true, vmess: true, wireguard: true
  };
  var RESERVED = /^(?:global|direct|compatible|pass|reject(?:-?drop)?|dns|rematch|guard-?probe)$/i;

  function hasKey(obj, key) {
    return Object.prototype.hasOwnProperty.call(obj, key);
  }

  function hasNonEmptyList(obj, key) {
    return Array.isArray(obj[key]) && obj[key].length > 0;
  }

  var rawGroups = Array.isArray(config["proxy-groups"]) ? config["proxy-groups"] : [];
  var groups = rawGroups.filter(function (group) {
    return group && typeof group === "object" && group.name !== PROBE_GROUP;
  });

  var rawListeners = Array.isArray(config.listeners) ? config.listeners : [];
  var listeners = rawListeners.filter(function (listener) {
    return listener && typeof listener === "object" && listener.name !== PROBE_INBOUND;
  });

  var portKeys = ["mixed-port", "port", "socks-port", "redir-port", "tproxy-port"];
  for (var i = 0; i < portKeys.length; i++) {
    if (Number(config[portKeys[i]]) === PROBE_PORT) {
      throw new Error("Guard 专用探测端口 " + PROBE_PORT + " 已被使用");
    }
  }
  for (var j = 0; j < listeners.length; j++) {
    if (Number(listeners[j].port) === PROBE_PORT) {
      throw new Error("Guard 专用探测端口 " + PROBE_PORT + " 已被使用");
    }
  }

  var groupNames = Object.create(null);
  for (var g = 0; g < groups.length; g++) {
    if (typeof groups[g].name === "string") {
      groupNames[groups[g].name] = true;
    }
  }

  var proxies = Array.isArray(config.proxies) ? config.proxies : [];
  var nameCounts = Object.create(null);
  for (var p = 0; p < proxies.length; p++) {
    var item = proxies[p];
    if (!item || typeof item.name !== "string") continue;
    nameCounts[item.name] = (nameCounts[item.name] || 0) + 1;
  }
  if (hasKey(nameCounts, PROBE_GROUP) || hasKey(nameCounts, "REJECT") || hasKey(groupNames, "REJECT")) {
    throw new Error("Guard-Probe 或 REJECT 名称被订阅占用");
  }

  var candidates = [];
  for (var k = 0; k < proxies.length; k++) {
    var node = proxies[k];
    if (!node || typeof node.name !== "string") continue;
    var trimmed = node.name.trim();
    if (!trimmed || RESERVED.test(trimmed)) continue;
    var nodeType = String(node.type || "").trim().toLowerCase();
    if (hasKey(RELAY_TYPES, nodeType) && nameCounts[node.name] === 1 && !hasKey(groupNames, node.name)) {
      candidates.push(node.name);
    }
  }

  // 1. 关闭顶层 IPv6
  config.ipv6 = false;

  // 2. 非破坏性补齐 TUN 基线（保留订阅与用户已有配置，不清空排除网段）
  var tun = (config.tun && typeof config.tun === "object") ? Object.assign({}, config.tun) : {};
  tun.enable = true;
  tun["auto-route"] = true;
  tun["strict-route"] = true;
  if (!tun.stack) tun.stack = "system";
  if (!tun.device) tun.device = "Mihomo";
  if (typeof tun["auto-detect-interface"] !== "boolean") tun["auto-detect-interface"] = true;
  if (typeof tun["endpoint-independent-nat"] !== "boolean") tun["endpoint-independent-nat"] = true;
  if (!tun.mtu) tun.mtu = 1500;
  if (!hasNonEmptyList(tun, "dns-hijack")) tun["dns-hijack"] = ["any:53", "tcp://any:53"];
  if (!hasNonEmptyList(tun, "route-exclude-address")) {
    tun["route-exclude-address"] = [
      "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "127.0.0.0/8",
      "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32",
      "fc00::/7", "fe80::/10", "::1/128"
    ];
  }
  config.tun = tun;

  // 3. 非破坏性补齐 DNS 基线（保留订阅私有 proxy-server-nameserver / enhanced-mode / nameserver-policy）
  var dns = (config.dns && typeof config.dns === "object") ? Object.assign({}, config.dns) : {};
  dns.enable = true;
  dns.ipv6 = false;
  if (!dns["enhanced-mode"]) dns["enhanced-mode"] = "fake-ip";
  if (typeof dns["use-hosts"] !== "boolean") dns["use-hosts"] = true;
  if (typeof dns["respect-rules"] !== "boolean") dns["respect-rules"] = true;
  if (!hasNonEmptyList(dns, "default-nameserver")) {
    dns["default-nameserver"] = ["223.5.5.5", "119.29.29.29", "114.114.114.114"];
  }
  if (!hasNonEmptyList(dns, "proxy-server-nameserver")) {
    dns["proxy-server-nameserver"] = ["https://dns.alidns.com/dns-query", "https://doh.pub/dns-query", "223.5.5.5"];
  }
  if (!hasNonEmptyList(dns, "nameserver")) {
    dns.nameserver = ["https://dns.alidns.com/dns-query", "https://doh.pub/dns-query", "223.5.5.5", "119.29.29.29"];
  }
  if (!hasNonEmptyList(dns, "fallback")) {
    dns.fallback = [
      "https://1.1.1.1/dns-query",
      "https://dns.google/dns-query",
      "https://cloudflare-dns.com/dns-query"
    ];
  }
  if (!dns["fallback-filter"] || typeof dns["fallback-filter"] !== "object") {
    dns["fallback-filter"] = { geoip: true, "geoip-code": "CN", geosite: ["gfw"] };
  }
  if (dns.listen === ":53") {
    delete dns.listen;
  }
  config.dns = dns;

  // 4. 置顶补齐 Claude 进程与全套关联域名分流规则（保留本机回环/局域网直连，防止影响本地 OAuth 与 MCP）
  var rawRules = Array.isArray(config.rules) ? config.rules : [];
  var proxyTarget = "";
  for (var r = 0; r < rawRules.length; r++) {
    if (typeof rawRules[r] !== "string") continue;
    var parts = rawRules[r].split(",");
    if (parts.length >= 2) {
      var kind = parts[0].trim().toUpperCase();
      var target = (kind === "MATCH" ? parts[1] : (parts.length >= 3 ? parts[2] : "")).trim();
      if (
        (kind === "MATCH" || (kind === "DOMAIN-SUFFIX" && parts[1].trim().toLowerCase() === "claude.ai")) &&
        hasKey(groupNames, target) &&
        !RESERVED.test(target)
      ) {
        proxyTarget = target;
        if (kind === "DOMAIN-SUFFIX") break;
      }
    }
  }
  if (!proxyTarget) {
    for (var s = 0; s < groups.length; s++) {
      if (groups[s].type === "select" && typeof groups[s].name === "string" && !RESERVED.test(groups[s].name.trim())) {
        proxyTarget = groups[s].name;
        break;
      }
    }
  }
  if (proxyTarget) {
    var pinnedRules = [
      "DOMAIN-SUFFIX,localhost,DIRECT",
      "DOMAIN-SUFFIX,local,DIRECT",
      "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
      "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
      "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
      "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
      "PROCESS-NAME,claude.exe," + proxyTarget,
      "DOMAIN-SUFFIX,claude.ai," + proxyTarget,
      "DOMAIN-SUFFIX,anthropic.com," + proxyTarget,
      "DOMAIN-SUFFIX,claudeusercontent.com," + proxyTarget,
      "DOMAIN-SUFFIX,claude.com," + proxyTarget,
      "DOMAIN-SUFFIX,clau.de," + proxyTarget,
      "DOMAIN-SUFFIX,challenges.cloudflare.com," + proxyTarget,
      "DOMAIN-SUFFIX,statsigapi.net," + proxyTarget,
      "DOMAIN-SUFFIX,featuregates.org," + proxyTarget,
      "DOMAIN-SUFFIX,sentry.io," + proxyTarget,
      "DOMAIN-SUFFIX,stripe.com," + proxyTarget,
      "DOMAIN-SUFFIX,intercom.io," + proxyTarget,
      "DOMAIN-SUFFIX,intercomcdn.com," + proxyTarget
    ];
    var pinnedSet = Object.create(null);
    for (var pr = 0; pr < pinnedRules.length; pr++) {
      pinnedSet[pinnedRules[pr].toLowerCase()] = true;
    }
    var restRules = rawRules.filter(function (rule) {
      return typeof rule !== "string" || !hasKey(pinnedSet, rule.trim().toLowerCase());
    });
    config.rules = pinnedRules.concat(restRules);
  }

  // 5. 注入本机隔离体检策略组与回环监听器（仅绑定 127.0.0.1:17897，不影响 allow-lan / 7897）
  var probeGroup = {
    name: PROBE_GROUP,
    type: "select",
    "empty-fallback": "REJECT",
    "default-selected": "REJECT",
    proxies: ["REJECT"].concat(candidates)
  };
  config["proxy-groups"] = [probeGroup].concat(groups);
  config.listeners = listeners.concat([{
    name: PROBE_INBOUND,
    type: "http",
    listen: "127.0.0.1",
    port: PROBE_PORT,
    proxy: PROBE_GROUP,
    users: []
  }]);

  return config;
}
