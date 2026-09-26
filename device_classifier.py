#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Best-effort local device type classification.

Classification is intentionally conservative. It relies only on names/vendor
strings already discovered on the local network and does not probe devices
beyond the existing discovery process.
"""

from __future__ import annotations


def classify_device(name: str = "", vendor: str = "", custom_name: str = "") -> str:
    text = " ".join([custom_name, name, vendor]).lower()

    phone_markers = (
        "iphone",
        "android",
        "pixel",
        "galaxy",
        "samsung",
        "motorola",
        "moto ",
        "oneplus",
        "xiaomi",
        "redmi",
        "oppo",
        "vivo",
        "huawei",
        "honor",
        "phone",
        "mobile",
    )
    tablet_markers = ("ipad", "tablet", "galaxy tab")
    tv_markers = ("roku", "fire tv", "chromecast", "apple tv", "smart tv", "bravia", "webos")
    computer_markers = ("legion", "macbook", "desktop", "laptop", "windows", "linux", "imac")
    printer_markers = ("printer", "brother", "epson", "canon", "laserjet", "officejet")

    if any(marker in text for marker in tablet_markers):
        return "TABLET"
    if any(marker in text for marker in phone_markers):
        return "PHONE"
    if any(marker in text for marker in tv_markers):
        return "TV/STREAMING"
    if any(marker in text for marker in printer_markers):
        return "PRINTER"
    if any(marker in text for marker in computer_markers):
        return "COMPUTER"

    return "UNKNOWN"
