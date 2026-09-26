#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Experimental modern Linux entry point for the KickThemOut fork.

Copyright (C) 2017-18 Nikolaos Kamarinakis & David Schütz
Modernization work Copyright (C) 2026 contributors to this fork.

Distributed under the MIT License included with this repository.

This first milestone modernizes local network discovery and device rescanning.
The original kickthemout.py remains untouched while this entry point is tested.
"""

from __future__ import annotations

import os
import socket
import sys
from dataclasses import dataclass
from time import sleep

import scan
from network_info import NetworkDiscoveryError, NetworkInfo, detect_network


BLUE = "\33[94m"
RED = "\033[91m"
WHITE = "\33[97m"
YELLOW = "\33[93m"
MAGENTA = "\033[1;35m"
GREEN = "\033[1;32m"
END = "\033[0m"


@dataclass
class Device:
    ip: str
    mac: str
    name: str = "Unknown"
    vendor: str = ""
    protected: bool = False


def require_root() -> None:
    if os.geteuid() != 0:
        print(
            f"\n{RED}ERROR: This program must be run with root privileges.{END}\n"
            f"\t{GREEN}$ sudo python3 kickthemout_modern.py{END}\n"
        )
        raise SystemExit(1)


def heading() -> None:
    spaces = " " * 76
    sys.stdout.write(
        GREEN
        + spaces
        + """
    █  █▀ ▄█ ▄█▄    █  █▀    ▄▄▄▄▀  ▄  █ ▄███▄   █▀▄▀█  ████▄   ▄      ▄▄▄▄▀
    █▄█   ██ █▀ ▀▄  █▄█   ▀▀▀ █    █   █ █▀   ▀  █ █ █  █   █    █  ▀▀▀ █
    █▀▄   ██ █   ▀  █▀▄       █    ██▀▀█ ██▄▄    █ ▄ █  █   █ █   █     █
    █  █  ▐█ █▄  ▄▀ █  █     █     █   █ █▄   ▄▀ █   █  ▀████ █   █    █
     █    ▐ ▀███▀    █     ▀         █  ▀███▀      █         █▄ ▄█   ▀
     ▀               ▀               ▀             ▀           ▀▀▀
    """
        + END
        + BLUE
        + "\n"
        + f"{YELLOW}Modern Linux Fork ({RED}KickThemOut{YELLOW}){BLUE}".center(98)
        + "\n"
        + f"Version: {YELLOW}0.3-dev{END}\n".center(86)
    )


def print_network(info: NetworkInfo) -> None:
    print(f"\n{BLUE}Network detected:{END}\n")
    print(f"\t{WHITE}Interface : {GREEN}{info.interface}{END}")
    print(f"\t{WHITE}Local IP  : {GREEN}{info.local_ip}{END}")
    print(f"\t{WHITE}MAC       : {GREEN}{info.mac}{END}")
    print(f"\t{WHITE}Gateway   : {GREEN}{info.gateway}{END}")
    print(f"\t{WHITE}Subnet    : {GREEN}{info.subnet}{END}\n")


def discover_devices(info: NetworkInfo) -> list[Device]:
    print(f"{GREEN}Scanning your network, hang on...{END}")

    devices_by_ip: dict[str, Device] = {}

    devices_by_ip[info.local_ip] = Device(
        ip=info.local_ip,
        mac=info.mac,
        name=socket.gethostname() or "This Computer",
        protected=True,
    )

    raw_devices = scan.scanNetwork(info.subnet)

    for item in raw_devices:
        if not item:
            continue

        ip = str(item[0])
        mac = str(item[1]).lower() if len(item) > 1 and item[1] else "unknown"
        hostname = str(item[2]).strip() if len(item) > 2 and item[2] else ""
        vendor = str(item[3]).strip() if len(item) > 3 and item[3] else ""
        name = hostname or vendor or "Unknown"
        protected = ip in {info.local_ip, info.gateway} or mac == info.mac

        existing = devices_by_ip.get(ip)
        if existing:
            if existing.mac == "unknown" and mac != "unknown":
                existing.mac = mac
            if existing.name in {"Unknown", "This Computer"} and name != "Unknown":
                existing.name = name
            if not existing.vendor and vendor:
                existing.vendor = vendor
            existing.protected = existing.protected or protected
        else:
            devices_by_ip[ip] = Device(
                ip=ip,
                mac=mac,
                name=name,
                vendor=vendor,
                protected=protected,
            )

    if info.gateway not in devices_by_ip:
        devices_by_ip[info.gateway] = Device(
            ip=info.gateway,
            mac="unknown",
            name="Gateway",
            protected=True,
        )
    else:
        devices_by_ip[info.gateway].protected = True
        if devices_by_ip[info.gateway].name == "Unknown":
            devices_by_ip[info.gateway].name = "Gateway"

    devices = list(devices_by_ip.values())
    devices.sort(key=lambda d: tuple(int(part) for part in d.ip.split(".")))
    print(f"{GREEN}Scan complete. {len(devices)} device(s) found.{END}\n")
    return devices


def print_devices(devices: list[Device], info: NetworkInfo) -> None:
    if not devices:
        print(f"\n{YELLOW}No devices were discovered.{END}\n")
        return

    print(f"\n{BLUE}Discovered devices:{END}\n")
    print(f"\t{WHITE}{'#':<4} {'IP':<16} {'MAC':<19} {'NAME / VENDOR'}{END}")

    for index, device in enumerate(devices, start=1):
        labels = []
        if device.ip == info.gateway:
            labels.append("GATEWAY")
        if device.ip == info.local_ip or device.mac == info.mac:
            labels.append("THIS COMPUTER")
        if device.protected:
            labels.append("PROTECTED")

        suffix = f" {YELLOW}[{' / '.join(labels)}]{END}" if labels else ""
        display_name = device.name
        if device.vendor and device.vendor.lower() != device.name.lower():
            display_name = f"{device.name} ({device.vendor})"

        print(
            f"\t{YELLOW}[{RED}{index}{YELLOW}]{WHITE} "
            f"{device.ip:<16} {device.mac:<19} {display_name}{suffix}"
        )
    print(END)


def option_banner() -> None:
    print("Choose an option from the menu:\n")
    sleep(0.1)
    print(f"\t{YELLOW}[{RED}1{YELLOW}]{WHITE} Rescan Devices")
    print(f"\t{YELLOW}[{RED}2{YELLOW}]{WHITE} View Devices")
    print(f"\t{YELLOW}[{RED}3{YELLOW}]{WHITE} Block Device {YELLOW}[coming next]{WHITE}")
    print(f"\t{YELLOW}[{RED}4{YELLOW}]{WHITE} Timed Block {YELLOW}[coming next]{WHITE}")
    print(f"\t{YELLOW}[{RED}5{YELLOW}]{WHITE} Block Until Time {YELLOW}[coming next]{WHITE}")
    print(f"\t{YELLOW}[{RED}6{YELLOW}]{WHITE} View Blocked Devices {YELLOW}[coming next]{WHITE}")
    print(f"\t{YELLOW}[{RED}7{YELLOW}]{WHITE} Restore Device {YELLOW}[coming next]{WHITE}")
    print(f"\t{YELLOW}[{RED}8{YELLOW}]{WHITE} Restore All {YELLOW}[coming next]{WHITE}")
    print(f"\n\t{YELLOW}[{RED}0{YELLOW}]{WHITE} Exit\n")


def prompt() -> str:
    return input(f"{BLUE}kickthemout{WHITE}> {END}").strip().lower()


def main() -> None:
    require_root()
    heading()

    try:
        info = detect_network()
    except NetworkDiscoveryError as exc:
        print(f"\n{RED}ERROR: Network discovery failed: {GREEN}{exc}{END}\n")
        raise SystemExit(1)

    print_network(info)

    try:
        devices = discover_devices(info)
    except Exception as exc:
        print(f"{RED}ERROR: Network scanning failed: {GREEN}{exc}{END}\n")
        devices = [
            Device(ip=info.gateway, mac="unknown", name="Gateway", protected=True),
            Device(
                ip=info.local_ip,
                mac=info.mac,
                name=socket.gethostname() or "This Computer",
                protected=True,
            ),
        ]

    while True:
        option_banner()
        choice = prompt()

        if choice == "1":
            try:
                info = detect_network()
                print_network(info)
                devices = discover_devices(info)
                print_devices(devices, info)
            except Exception as exc:
                print(f"\n{RED}ERROR: Rescan failed: {GREEN}{exc}{END}\n")

        elif choice == "2":
            print_devices(devices, info)

        elif choice in {"3", "4", "5", "6", "7", "8"}:
            print(f"\n{YELLOW}That feature is planned for the next milestone.{END}\n")

        elif choice in {"0", "e", "exit", "q", "quit"}:
            print(f"\n{GREEN}Thanks for dropping by. Catch ya later!{END}\n")
            return

        else:
            print(f"\n{RED}ERROR: Invalid option.{END}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{GREEN}Interrupted. Exiting cleanly.{END}\n")
