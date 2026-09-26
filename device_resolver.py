#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Best-effort local device name resolution helpers.

All lookups are local to the LAN or local resolver configuration. Optional
system tools are used when present and silently skipped when unavailable.
"""

from __future__ import annotations

import shutil
import socket
import subprocess


def _run_optional(command: list[str], timeout: float = 2.0) -> str:
    if not shutil.which(command[0]):
        return ""
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.strip()


def reverse_dns_name(ip: str) -> str:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror, OSError):
        return ""
    hostname = hostname.strip().rstrip(".")
    return hostname if hostname and hostname != ip else ""


def mdns_name(ip: str) -> str:
    """Resolve with Avahi when avahi-resolve-address is installed."""
    output = _run_optional(["avahi-resolve-address", ip])
    if not output:
        return ""

    # Typical output: "192.168.1.20\tdevice-name.local"
    parts = output.split()
    if len(parts) < 2:
        return ""
    name = parts[-1].strip().rstrip(".")
    return name if name and name != ip else ""


def netbios_name(ip: str) -> str:
    """Resolve a NetBIOS computer name when Samba's nmblookup is installed."""
    output = _run_optional(["nmblookup", "-A", ip])
    if not output:
        return ""

    for line in output.splitlines():
        line = line.strip()
        if "<00>" not in line or "GROUP" in line.upper():
            continue
        name = line.split()[0].strip()
        if name and name != ip:
            return name
    return ""


def resolve_device_name(ip: str, nmap_name: str = "", vendor: str = "") -> tuple[str, str]:
    """Return (best_name, source) using progressively broader local lookups."""
    if nmap_name and nmap_name != "Unknown":
        return nmap_name, "nmap"

    name = reverse_dns_name(ip)
    if name:
        return name, "reverse-dns"

    name = mdns_name(ip)
    if name:
        return name, "mdns"

    name = netbios_name(ip)
    if name:
        return name, "netbios"

    if vendor:
        return vendor, "vendor"

    return "Unknown", "unknown"
