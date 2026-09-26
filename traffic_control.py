#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Gateway-only traffic-control readiness checks for the modern Linux fork.

This module intentionally does not try to affect peer devices unless this Linux
machine is actually forwarding/routing traffic. That avoids false positives on
ordinary Wi-Fi client setups.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


@dataclass
class GatewayReadiness:
    ip_forwarding: bool
    nft_available: bool
    tc_available: bool
    ready_for_block: bool
    ready_for_lag: bool
    notes: list[str]


def _read_ip_forwarding() -> bool:
    try:
        value = subprocess.check_output(
            ["sysctl", "-n", "net.ipv4.ip_forward"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        return value == "1"
    except (OSError, subprocess.CalledProcessError):
        return False


def check_gateway_readiness() -> GatewayReadiness:
    ip_forwarding = _read_ip_forwarding()
    nft_available = shutil.which("nft") is not None
    tc_available = shutil.which("tc") is not None

    notes: list[str] = []

    if not ip_forwarding:
        notes.append(
            "IPv4 forwarding is disabled, so this machine is not currently acting as an IPv4 router."
        )

    if not nft_available:
        notes.append("nftables command 'nft' is not installed.")

    if not tc_available:
        notes.append("traffic-control command 'tc' is not installed.")

    ready_for_block = ip_forwarding and nft_available
    ready_for_lag = ip_forwarding and tc_available

    if ip_forwarding:
        notes.append(
            "IPv4 forwarding is enabled. Confirm the target device's traffic actually traverses this machine before applying gateway rules."
        )

    return GatewayReadiness(
        ip_forwarding=ip_forwarding,
        nft_available=nft_available,
        tc_available=tc_available,
        ready_for_block=ready_for_block,
        ready_for_lag=ready_for_lag,
        notes=notes,
    )
