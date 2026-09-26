#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Safe blocking backend interface for the modern KickThemOut fork.

The UI can select and validate devices independently from the mechanism that
enforces access control. Backends should use an authorized router, firewall,
hotspot, or other legitimate network-control API.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass
class BlockRecord:
    ip: str
    mac: str
    name: str
    started_at: datetime
    ends_at: datetime | None = None


class BlockBackend:
    """Interface for a legitimate network access-control backend."""

    def block(self, *, ip: str, mac: str, name: str) -> None:
        raise NotImplementedError(
            "No authorized router/firewall blocking backend is configured."
        )

    def restore(self, *, ip: str, mac: str) -> None:
        raise NotImplementedError(
            "No authorized router/firewall blocking backend is configured."
        )


class BlockManager:
    def __init__(self, backend: BlockBackend | None = None) -> None:
        self.backend = backend or BlockBackend()
        self._blocked: dict[str, BlockRecord] = {}

    @staticmethod
    def validate_target(device, info) -> tuple[bool, str]:
        if device.protected:
            return False, "Protected devices cannot be blocked."
        if device.ip == info.gateway:
            return False, "The gateway cannot be blocked."
        if device.ip == info.local_ip or device.mac.lower() == info.mac.lower():
            return False, "This computer cannot be blocked."
        if device.mac == "unknown":
            return False, "The device has no usable MAC address."
        return True, ""

    def block(self, device, info) -> tuple[bool, str]:
        ok, reason = self.validate_target(device, info)
        if not ok:
            return False, reason

        key = device.mac.lower()
        if key in self._blocked:
            return False, "Device is already blocked."

        name = device.custom_name or device.name
        try:
            self.backend.block(ip=device.ip, mac=device.mac, name=name)
        except NotImplementedError as exc:
            return False, str(exc)

        self._blocked[key] = BlockRecord(
            ip=device.ip,
            mac=device.mac,
            name=name,
            started_at=datetime.now(),
        )
        return True, f"{name} blocked."

    def restore(self, mac: str) -> tuple[bool, str]:
        key = mac.lower()
        record = self._blocked.get(key)
        if record is None:
            return False, "Device is not currently blocked."

        try:
            self.backend.restore(ip=record.ip, mac=record.mac)
        except NotImplementedError as exc:
            return False, str(exc)

        del self._blocked[key]
        return True, f"{record.name} restored."

    def list_blocked(self) -> list[BlockRecord]:
        return list(self._blocked.values())
