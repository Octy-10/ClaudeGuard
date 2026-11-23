"""Create macOS bundle plists and check Developer ID provisioning inputs."""

import os
import ipaddress
import runpy
import plistlib
import sys
from pathlib import Path

APP_ID = "io.github.octy-10.claudeguard"
FILTER_ID = APP_ID + ".filter"
FILTER_ENTITLEMENT = "com.apple.developer.networking.networkextension"
FILTER_VALUE = "content-filter-provider-systemextension"
INSTALL_ENTITLEMENT = "com.apple.developer.system-extension.install"
USAGE = "Claude Guard limits outbound Claude Desktop connections to its local proxy route."


def write(path: Path, data: dict) -> None:
    path.write_bytes(plistlib.dumps(data))


def profile_entitlements(profile: Path, bundle: str, team: str, *, host: bool) -> dict:
    data = plistlib.loads(profile.read_bytes())
    ent = data["Entitlements"]
    if team not in data["TeamIdentifier"] or FILTER_VALUE not in ent.get(FILTER_ENTITLEMENT, []):
        raise SystemExit(f"{bundle} needs the team's Developer ID Network Extension provisioning profile")
    app_identifier = ent.get("com.apple.application-identifier") or ent.get("application-identifier")
    if app_identifier != f"{team}.{bundle}":
        raise SystemExit(f"Provisioning profile bundle ID mismatch for {bundle}")
    result = {
        "com.apple.application-identifier": app_identifier,
        "com.apple.developer.team-identifier": team,
        FILTER_ENTITLEMENT: [FILTER_VALUE],
    }
    if host:
        result[INSTALL_ENTITLEMENT] = True
    return result


def main() -> None:
    contents, extension, work = map(Path, sys.argv[1:4])
    version, team, identity = sys.argv[4:]
    config = runpy.run_path("guard/config.py")
    with (work / "ProtectedAddresses.swift").open("w", encoding="utf-8") as generated:
        for family in (4, 6):
            generated.write(f"let protectedIPv{family}: [AddressPrefix] = [\n")
            for cidr in config[f"ANTHROPIC_CIDRS_V{family}"]:
                network = ipaddress.ip_network(cidr)
                generated.write(f"    AddressPrefix(bytes: {list(network.network_address.packed)}, bits: {network.prefixlen}),\n")
            generated.write("]\n")
    info = contents / "Info.plist"
    info_data = plistlib.loads(info.read_bytes())
    info_data.update(LSMinimumSystemVersion="15.0", NSSystemExtensionUsageDescription=USAGE, CFBundleVersion=version)
    write(info, info_data)
    write(extension / "Info.plist", {
        "CFBundleIdentifier": FILTER_ID,
        "CFBundlePackageType": "SYSX",
        "CFBundleExecutable": "ClaudeGuardFilter",
        "CFBundleName": "Claude Guard Network Filter",
        "CFBundleVersion": version,
        "CFBundleShortVersionString": version,
        "LSMinimumSystemVersion": "15.0",
        "NSSystemExtensionUsageDescription": USAGE,
        "NetworkExtension": {
            "NEMachServiceName": f"{team}.{FILTER_ID}",
            "NEProviderClasses": {
                "com.apple.networkextension.filter-data": "GuardFilterDataProvider",
                "com.apple.networkextension.filter-packet": "GuardPacketProvider",
            },
        },
    })
    agent_label = APP_ID + ".login"
    write(contents / "Library" / "LaunchAgents" / f"{agent_label}.plist", {
        "Label": agent_label,
        "BundleProgram": "Contents/MacOS/ClaudeGuard",
        "ProgramArguments": ["ClaudeGuard", "--minimized"],
        "RunAtLoad": True,
        "LimitLoadToSessionType": "Aqua",
    })
    if identity != "-":
        app_profile = work / (Path(os.environ["MACOS_APP_PROFILE"]).name + ".plist")
        filter_profile = work / (Path(os.environ["MACOS_FILTER_PROFILE"]).name + ".plist")
        write(work / "app.entitlements", profile_entitlements(app_profile, APP_ID, team, host=True))
        filter_ent = profile_entitlements(filter_profile, FILTER_ID, team, host=False)
        filter_ent["com.apple.security.app-sandbox"] = True
        write(work / "filter.entitlements", filter_ent)


if __name__ == "__main__":
    main()
