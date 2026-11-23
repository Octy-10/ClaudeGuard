// Clash Verge Rev 全局扩展脚本（可选）：自动为任意订阅置顶 Claude 进程与相关域名分流规则（不修改 TUN/DNS）

function main(config, profileName) {
  if (!config || typeof config !== "object") {
    return config;
  }

  var RESERVED = /^(?:global|direct|compatible|pass|reject(?:-?drop)?|dns|rematch|guard-?probe)$/i;
  var AI_GROUP_RE = /claude|openai|chatgpt|人工智能|(?:^|[^a-z])ai(?:[^a-z]|$)/i;

  var rawGroups = Array.isArray(config["proxy-groups"]) ? config["proxy-groups"] : [];
  var groupNames = Object.create(null);
  var selectGroups = [];

  for (var i = 0; i < rawGroups.length; i++) {
    var g = rawGroups[i];
    if (!g || typeof g !== "object" || typeof g.name !== "string") continue;
    var name = g.name;
    if (RESERVED.test(name.trim())) continue;
    groupNames[name] = true;
    if (g.type === "select") {
      selectGroups.push(name);
    }
  }

  // 1. 优先匹配 AI 专用手动选择组（如 🤖AI网站）
  var proxyTarget = "";
  for (var a = 0; a < selectGroups.length; a++) {
    if (AI_GROUP_RE.test(selectGroups[a])) {
      proxyTarget = selectGroups[a];
      break;
    }
  }

  // 2. 其次复用当前订阅 MATCH 规则的兜底策略组
  var rawRules = Array.isArray(config.rules) ? config.rules : [];
  if (!proxyTarget) {
    for (var r = 0; r < rawRules.length; r++) {
      if (typeof rawRules[r] !== "string") continue;
      var parts = rawRules[r].split(",");
      if (parts.length >= 2 && parts[0].trim().toUpperCase() === "MATCH") {
        var target = parts[1].trim();
        if (Object.prototype.hasOwnProperty.call(groupNames, target)) {
          proxyTarget = target;
          break;
        }
      }
    }
  }

  // 3. 兜底使用第一个手动选择组
  if (!proxyTarget && selectGroups.length > 0) {
    proxyTarget = selectGroups[0];
  }

  if (!proxyTarget) {
    return config;
  }

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
  for (var p = 0; p < pinnedRules.length; p++) {
    pinnedSet[pinnedRules[p].toLowerCase()] = true;
  }

  var restRules = rawRules.filter(function (rule) {
    return typeof rule !== "string" || !Object.prototype.hasOwnProperty.call(pinnedSet, rule.trim().toLowerCase());
  });

  config.rules = pinnedRules.concat(restRules);
  return config;
}
