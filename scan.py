#!/usr/bin/env python3
# -.- coding: utf-8 -.-
# scan.py

"""
Copyright (C) 2017-18 Nikolaos Kamarinakis (nikolaskam@gmail.com) & David Schütz (xdavid@protonmail.com)
See License at nikolaskama.me (https://nikolaskama.me/kickthemoutproject)
"""

import nmap

# perform a network scan with nmap
def scanNetwork(network):
    returnlist = []
    nm = nmap.PortScanner()
    a = nm.scan(hosts=network, arguments='-sn -R')

    for _, v in a.get('scan', {}).items():
        if str(v.get('status', {}).get('state')) != 'up':
            continue

        addresses = v.get('addresses', {})
        ip = str(addresses.get('ipv4', ''))
        if not ip:
            continue

        mac = str(addresses.get('mac', '')).lower()

        hostname = ''
        for entry in v.get('hostnames', []):
            candidate = str(entry.get('name', '')).strip()
            if candidate:
                hostname = candidate
                break

        vendor = ''
        if mac:
            vendor_map = v.get('vendor', {})
            vendor = str(vendor_map.get(mac.upper(), '') or vendor_map.get(mac, '')).strip()

        # Preserve the original list-based return format so the legacy script
        # can still use item[0] and item[1]. Modern callers may additionally
        # read hostname and vendor from item[2] and item[3].
        returnlist.append([ip, mac, hostname, vendor])

    return returnlist
