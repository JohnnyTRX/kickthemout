#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Modern Linux network discovery helpers for KickThemOut forks.

This module intentionally uses Linux's `ip` command for interface, route,
address, subnet and MAC discovery instead of relying on Scapy's internal
routing table. It keeps discovery local and deterministic.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class NetworkInfo:
    interface: str
    local_ip: str
    mac: str
    gateway: str
    subnet: str


class NetworkDiscoveryError(RuntimeError):
    pass


def _run_ip(*args: str) -> str:
    try:
        result = subprocess.run(
            ["ip", *args],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise NetworkDiscoveryError("The Linux `ip` command is not installed.") from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or str(exc)).strip()
        raise NetworkDiscoveryError(detail or "Linux network discovery failed.") from exc
    return result.stdout.strip()


def get_default_route() -> tuple[str, str]:
    """Return (gateway_ip, interface) for the active IPv4 default route."""
    output = _run_ip("-4", "route", "show", "default")
    for line in output.splitlines():
        gateway_match = re.search(r"\bvia\s+(\S+)", line)
        interface_match = re.search(r"\bdev\s+(\S+)", line)
        if gateway_match and interface_match:
            return gateway_match.group(1), interface_match.group(1)
    raise NetworkDiscoveryError("No active IPv4 default route was found.")


def get_interface_address(interface: str) -> tuple[str, str]:
    """Return (local_ip, subnet_cidr) for an interface."""
    output = _run_ip("-o", "-4", "addr", "show", "dev", interface, "scope", "global")
    for line in output.splitlines():
        match = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+/\d+)\b", line)
        if not match:
            continue
        address = ipaddress.ip_interface(match.group(1))
        return str(address.ip), str(address.network)
    raise NetworkDiscoveryError(f"No IPv4 address was found on interface {interface}.")


def get_interface_mac(interface: str) -> str:
    output = _run_ip("-o", "link", "show", "dev", interface)
    match = re.search(r"\blink/ether\s+([0-9a-fA-F:]{17})\b", output)
    if not match:
        raise NetworkDiscoveryError(f"No MAC address was found on interface {interface}.")
    return match.group(1).lower()


def detect_network() -> NetworkInfo:
    gateway, interface = get_default_route()
    local_ip, subnet = get_interface_address(interface)
    mac = get_interface_mac(interface)

    # Basic sanity check so a malformed route never reaches the scanner.
    if ipaddress.ip_address(gateway) not in ipaddress.ip_network(subnet, strict=False):
        raise NetworkDiscoveryError(
            f"Gateway {gateway} is outside detected subnet {subnet}."
        )

    return NetworkInfo(
        interface=interface,
        local_ip=local_ip,
        mac=mac,
        gateway=gateway,
        subnet=subnet,
    )
