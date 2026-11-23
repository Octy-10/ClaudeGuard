const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "../clash-verge-override.js"), "utf8");
const apply = (input, windowsPreset = true) => {
  const script = windowsPreset ? source : source.replace("APPLY_WIN_TUN_DNS_PRESET = true", "APPLY_WIN_TUN_DNS_PRESET = false");
  // Clash Verge compiles the script and main invocation together in this block.
  const wrapped = "try {\n" + script + "\nJSON.stringify(main(input, 'fixture'))\n} catch (err) { String(err) }";
  const result = vm.runInNewContext(wrapped, { input: structuredClone(input) });
  if (!result.startsWith("{")) throw new Error(result);
  return JSON.parse(result);
};
const remote = (name) => ({ name, type: "vless" });

test("script runs without rewriting daily subscription rules or VM port", () => {
  const groups = [{ name: "Daily", type: "select", proxies: ["DIRECT", "Remote"] }];
  const rules = ["DOMAIN-SUFFIX,claude.ai,Daily", "MATCH,DIRECT"];
  const result = apply({ "allow-lan": true, "mixed-port": 7897, "proxy-groups": groups, rules, proxies: [remote("Remote")] });
  assert.deepEqual(result.rules, rules);
  assert.deepEqual(result["proxy-groups"].slice(1), groups);
  assert.equal(result["allow-lan"], true);
  assert.equal(result["mixed-port"], 7897);
  assert.deepEqual(result.listeners, [{
    name: "claude-guard-probe", type: "http", listen: "127.0.0.1", port: 17897, proxy: "Guard-Probe", users: [],
  }]);
  assert.deepEqual(apply(result), result);
});

test("probe starts with REJECT and excludes renamed direct and ambiguous nodes", () => {
  const result = apply({ proxies: [remote("Remote"), remote("Duplicate"), remote("Duplicate"), { name: "Local", type: "direct" }] });
  const probe = result["proxy-groups"][0];
  assert.equal(probe["default-selected"], "REJECT");
  assert.equal(probe["empty-fallback"], "REJECT");
  assert.deepEqual(probe.proxies, ["REJECT", "Remote"]);
  assert.deepEqual(apply({})["proxy-groups"][0].proxies, ["REJECT"]);
});

test("existing port collision does not overwrite the listener", () => {
  assert.throws(() => apply({ "mixed-port": 17897 }), /17897/);
  assert.throws(() => apply({ listeners: [{ name: "Existing", port: "17897" }] }), /17897/);
});

test("Windows TUN, loopback exclusions and DNS remain available", () => {
  const input = { tun: { mtu: 1280 }, dns: { listen: ":53", "nameserver-policy": { "test.invalid": ["system"] } } };
  const result = apply(input);
  assert.equal(result.tun["strict-route"], true);
  assert.equal(result.tun["route-exclude-address"].length, 10);
  assert.ok(result.tun["route-exclude-address"].includes("127.0.0.0/8"));
  assert.equal(result.dns["enhanced-mode"], "redir-host");
  assert.equal(result.ipv6, false);
  assert.equal(result.dns.ipv6, false);
  assert.equal(result.dns.listen, undefined);
  assert.deepEqual(result.dns["nameserver-policy"], input.dns["nameserver-policy"]);
  assert.deepEqual(apply(input, false).tun, input.tun);
});
