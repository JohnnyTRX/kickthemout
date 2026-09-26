#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Experimental modern Linux entry point for the KickThemOut fork.

Copyright (C) 2017-18 Nikolaos Kamarinakis & David Schütz
Modernization work Copyright (C) 2026 contributors to this fork.

Distributed under the MIT License included with this repository.
"""

from __future__ import annotations

from block_backend import BlockManager

import json
import os
import socket
import sys
from dataclasses import dataclass
from pathlib import Path
from time import sleep

import scan
from device_classifier import classify_device
from device_resolver import resolve_device_name
from network_info import NetworkDiscoveryError, NetworkInfo, detect_network


BLUE = "\33[94m"
RED = "\033[91m"
WHITE = "\33[97m"
YELLOW = "\33[93m"
MAGENTA = "\033[1;35m"
GREEN = "\033[1;32m"
END = "\033[0m"

DEVICE_NAMES_FILE = Path(__file__).with_name("device_names.json")


@dataclass
class Device:
    ip: str
    mac: str
    name: str = "Unknown"
    vendor: str = ""
    protected: bool = False
    custom_name: str = ""
    name_source: str = "unknown"
    device_type: str = "UNKNOWN"


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
        + f"Version: {YELLOW}0.6-dev{END}\n".center(86)
    )


def load_custom_names() -> dict[str, str]:
    if not DEVICE_NAMES_FILE.exists():
        return {}

    try:
        data = json.loads(DEVICE_NAMES_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}

    if not isinstance(data, dict):
        return {}

    return {
        str(mac).lower(): str(name).strip()
        for mac, name in data.items()
        if str(mac).strip() and str(name).strip()
    }


def save_custom_names(names: dict[str, str]) -> None:
    DEVICE_NAMES_FILE.write_text(
        json.dumps(dict(sorted(names.items())), indent=2) + "\n",
        encoding="utf-8",
    )


def print_network(info: NetworkInfo) -> None:
    print(f"\n{BLUE}Network detected:{END}\n")
    print(f"\t{WHITE}Interface : {GREEN}{info.interface}{END}")
    print(f"\t{WHITE}Local IP  : {GREEN}{info.local_ip}{END}")
    print(f"\t{WHITE}MAC       : {GREEN}{info.mac}{END}")
    print(f"\t{WHITE}Gateway   : {GREEN}{info.gateway}{END}")
    print(f"\t{WHITE}Subnet    : {GREEN}{info.subnet}{END}\n")


def discover_devices(info: NetworkInfo, custom_names: dict[str, str]) -> list[Device]:
    print(f"{GREEN}Scanning your network, hang on...{END}")

    devices_by_ip: dict[str, Device] = {}

    local_name = socket.gethostname() or "This Computer"
    local_custom = custom_names.get(info.mac.lower(), "")
    devices_by_ip[info.local_ip] = Device(
        ip=info.local_ip,
        mac=info.mac,
        name=local_name,
        protected=True,
        custom_name=local_custom,
        name_source="local",
        device_type="COMPUTER",
    )

    raw_devices = scan.scanNetwork(info.subnet)

    for item in raw_devices:
        if not item:
            continue

        ip = str(item[0])
        mac = str(item[1]).lower() if len(item) > 1 and item[1] else "unknown"
        nmap_name = str(item[2]).strip() if len(item) > 2 and item[2] else ""
        vendor = str(item[3]).strip() if len(item) > 3 and item[3] else ""
        name, name_source = resolve_device_name(ip, nmap_name, vendor)
        protected = ip in {info.local_ip, info.gateway} or mac == info.mac
        custom_name = custom_names.get(mac, "") if mac != "unknown" else ""
        device_type = classify_device(name=name, vendor=vendor, custom_name=custom_name)

        existing = devices_by_ip.get(ip)
        if existing:
            if existing.mac == "unknown" and mac != "unknown":
                existing.mac = mac
            if existing.name in {"Unknown", "This Computer"} and name != "Unknown":
                existing.name = name
                existing.name_source = name_source
            if not existing.vendor and vendor:
                existing.vendor = vendor
            if not existing.custom_name and custom_name:
                existing.custom_name = custom_name
            existing.protected = existing.protected or protected
            existing.device_type = classify_device(
                name=existing.name,
                vendor=existing.vendor,
                custom_name=existing.custom_name,
            )
            if existing.ip == info.local_ip or existing.mac == info.mac:
                existing.device_type = "COMPUTER"
        else:
            devices_by_ip[ip] = Device(
                ip=ip,
                mac=mac,
                name=name,
                vendor=vendor,
                protected=protected,
                custom_name=custom_name,
                name_source=name_source,
                device_type=device_type,
            )

    if info.gateway not in devices_by_ip:
        gateway_name, gateway_source = resolve_device_name(info.gateway)
        devices_by_ip[info.gateway] = Device(
            ip=info.gateway,
            mac="unknown",
            name=gateway_name if gateway_name != "Unknown" else "Gateway",
            protected=True,
            name_source=gateway_source if gateway_name != "Unknown" else "local",
            device_type="ROUTER",
        )
    else:
        gateway = devices_by_ip[info.gateway]
        gateway.protected = True
        gateway.device_type = "ROUTER"
        if gateway.name == "Unknown":
            gateway.name = "Gateway"
            gateway.name_source = "local"
        if gateway.mac != "unknown":
            gateway.custom_name = custom_names.get(gateway.mac, gateway.custom_name)

    devices = list(devices_by_ip.values())
    devices.sort(key=lambda d: tuple(int(part) for part in d.ip.split(".")))
    print(f"{GREEN}Scan complete. {len(devices)} device(s) found.{END}\n")
    return devices


def display_name(device: Device) -> str:
    if device.custom_name:
        detected = device.name
        if device.vendor and device.vendor.lower() != detected.lower():
            detected = f"{detected} / {device.vendor}"
        if detected and detected != "Unknown":
            return f"{device.custom_name} ({detected})"
        return device.custom_name

    if device.vendor and device.vendor.lower() != device.name.lower():
        return f"{device.name} ({device.vendor})"
    return device.name


def print_devices(devices: list[Device], info: NetworkInfo) -> None:
    if not devices:
        print(f"\n{YELLOW}No devices were discovered.{END}\n")
        return

    print(f"\n{BLUE}Discovered devices:{END}\n")
    print(f"\t{WHITE}{'#':<4} {'IP':<16} {'MAC':<19} {'TYPE':<13} {'NAME / VENDOR'}{END}")

    for index, device in enumerate(devices, start=1):
        labels = []
        if device.ip == info.gateway:
            labels.append("GATEWAY")
        if device.ip == info.local_ip or device.mac == info.mac:
            labels.append("THIS COMPUTER")
        if device.protected:
            labels.append("PROTECTED")

        suffix = f" {YELLOW}[{' / '.join(labels)}]{END}" if labels else ""
        print(
            f"\t{YELLOW}[{RED}{index}{YELLOW}]{WHITE} "
            f"{device.ip:<16} {device.mac:<19} {device.device_type:<13} "
            f"{display_name(device)}{suffix}"
        )
    print(END)


def manage_device_names(
    devices: list[Device], info: NetworkInfo, custom_names: dict[str, str]
) -> None:
    usable = [device for device in devices if device.mac != "unknown"]
    if not usable:
        print(f"\n{YELLOW}No devices with usable MAC addresses are available.{END}\n")
        return

    print_devices(devices, info)
    raw = input(
        f"{BLUE}Enter device number to rename, or press Enter to cancel{WHITE}> {END}"
    ).strip()
    if not raw:
        return

    try:
        index = int(raw) - 1
        device = devices[index]
    except (ValueError, IndexError):
        print(f"\n{RED}ERROR: Invalid device number.{END}\n")
        return

    if device.mac == "unknown":
        print(
            f"\n{YELLOW}That device has no usable MAC address, so its name cannot be saved reliably.{END}\n"
        )
        return

    current = device.custom_name or display_name(device)
    print(f"\n{WHITE}Selected: {GREEN}{device.ip}  {device.mac}  {current}{END}")
    new_name = input(
        f"{BLUE}New custom name (blank removes saved name){WHITE}> {END}"
    ).strip()

    mac = device.mac.lower()
    if new_name:
        custom_names[mac] = new_name
        device.custom_name = new_name
        device.device_type = classify_device(
            name=device.name, vendor=device.vendor, custom_name=device.custom_name
        )
        if device.ip == info.local_ip or device.mac == info.mac:
            device.device_type = "COMPUTER"
        save_custom_names(custom_names)
        print(f"\n{GREEN}Saved device name: {new_name}{END}\n")
    else:
        custom_names.pop(mac, None)
        device.custom_name = ""
        device.device_type = classify_device(name=device.name, vendor=device.vendor)
        if device.ip == info.local_ip or device.mac == info.mac:
            device.device_type = "COMPUTER"
        if device.ip == info.gateway:
            device.device_type = "ROUTER"
        save_custom_names(custom_names)
        print(f"\n{GREEN}Saved custom name removed.{END}\n")


def option_banner() -> None:
    print("Choose an option from the menu:\n")
    sleep(0.1)
    print(f"\t{YELLOW}[{RED}1{YELLOW}]{WHITE} Rescan Devices")
    print(f"\t{YELLOW}[{RED}2{YELLOW}]{WHITE} View Devices")
    print(f"\t{YELLOW}[{RED}3{YELLOW}]{WHITE} Block Device")
    print(f"\t{YELLOW}[{RED}4{YELLOW}]{WHITE} Timed Block {YELLOW}[coming next]{WHITE}")
    print(f"\t{YELLOW}[{RED}5{YELLOW}]{WHITE} Block Until Time {YELLOW}[coming next]{WHITE}")
    print(f"\t{YELLOW}[{RED}6{YELLOW}]{WHITE} View Blocked Devices {YELLOW}[coming next]{WHITE}")
    print(f"\t{YELLOW}[{RED}7{YELLOW}]{WHITE} Restore Device {YELLOW}[coming next]{WHITE}")
    print(f"\t{YELLOW}[{RED}8{YELLOW}]{WHITE} Restore All {YELLOW}[coming next]{WHITE}")
    print(f"\t{YELLOW}[{RED}9{YELLOW}]{WHITE} Manage Saved Device Names")
    print(f"\n\t{YELLOW}[{RED}0{YELLOW}]{WHITE} Exit\n")


def prompt() -> str:
    return input(f"{BLUE}kickthemout{WHITE}> {END}").strip().lower()


def main() -> None:
    require_root()
    heading()
    custom_names = load_custom_names()
    block_manager = BlockManager()

    try:
        info = detect_network()
    except NetworkDiscoveryError as exc:
        print(f"\n{RED}ERROR: Network discovery failed: {GREEN}{exc}{END}\n")
        raise SystemExit(1)

    print_network(info)

    try:
        devices = discover_devices(info, custom_names)
    except Exception as exc:
        print(f"{RED}ERROR: Network scanning failed: {GREEN}{exc}{END}\n")
        devices = [
            Device(ip=info.gateway, mac="unknown", name="Gateway", protected=True, device_type="ROUTER"),
            Device(
                ip=info.local_ip,
                mac=info.mac,
                name=socket.gethostname() or "This Computer",
                protected=True,
                custom_name=custom_names.get(info.mac.lower(), ""),
                name_source="local",
                device_type="COMPUTER",
            ),
        ]

    while True:
        option_banner()
        choice = prompt()

        if choice == "1":
            try:
                info = detect_network()
                custom_names = load_custom_names()
                print_network(info)
                devices = discover_devices(info, custom_names)
                print_devices(devices, info)
            except Exception as exc:
                print(f"\n{RED}ERROR: Rescan failed: {GREEN}{exc}{END}\n")

        elif choice == "2":
            print_devices(devices, info)

        elif choice == "9":
            manage_device_names(devices, info, custom_names)

        elif choice == "3":
            print_devices(devices, info)

            raw = input(
                f"{BLUE}Enter device number, or press Enter to cancel{WHITE}> {END}"
            ).strip()

            if not raw:
                continue

            try:
                index = int(raw) - 1
                device = devices[index]
            except (ValueError, IndexError):
                print(f"\n{RED}ERROR: Invalid device number.{END}\n")
                continue

            valid, reason = block_manager.validate_target(device, info)

            if not valid:
                print(f"\n{RED}{reason}{END}\n")
                continue

            success, message = block_manager.block(device, info)

            if success:
                print(f"\n{GREEN}{message}{END}\n")
            else:
                print(f"\n{RED}{message}{END}\n")

        elif choice in {"4", "5", "6", "7", "8"}:
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
