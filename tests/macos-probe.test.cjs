const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "../clash-macos-probe.js"), "utf8");
const apply = input => JSON.parse(vm.runInNewContext(`${source}\nJSON.stringify(main(config))`, { config: structuredClone(input) }));

test("preserves subscription routes and network settings and is idempotent", () => {
  const input = {
    rules: ["MATCH,DIRECT"], "mixed-port": 7897, "allow-lan": true,
    tun: { enable: false, device: "utun7" }, dns: { enable: true, nameserver: ["system"] }, ipv6: true,
    proxies: [{ name: "Remote", type: "ss" }],
  };
  const { listeners, "proxy-groups": groups, ...subscription } = apply(input);
  assert.deepEqual(subscription, input);
  assert.deepEqual(listeners, [
    { name: "claude-guard-probe", type: "http", listen: "127.0.0.1", port: 17897, proxy: "Guard-Probe", users: [] },
    { name: "claude-guard-app", type: "http", listen: "127.0.0.1", port: 17898, proxy: "Guard-Claude", users: [] },
  ]);
  assert.deepEqual(groups[0].proxies, ["REJECT", "Remote"]);
  assert.deepEqual(groups[1].proxies, ["REJECT", "Remote"]);
  assert.deepEqual(apply(apply(input)), apply(input));
});

test("rejects port or name collisions and filters ambiguous and direct nodes", () => {
  assert.throws(() => apply({ "mixed-port": 17897 }), /17897/);
  assert.throws(() => apply({ listeners: [{ name: "Clash", port: 17897 }] }), /17897/);
  assert.throws(() => apply({ listeners: [{ name: "Clash", port: 17898 }] }), /17898/);
  assert.throws(() => apply({ "proxy-groups": [{ name: "Guard-Probe", type: "select" }] }), /Guard-Probe/);
  const result = apply({ proxies: [{ name: "local", type: "direct" }, { name: "dup", type: "ss" }, { name: "dup", type: "vless" }] });
  assert.deepEqual(result["proxy-groups"][0].proxies, ["REJECT"]);
});
