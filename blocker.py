# blocker.py

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass
class BlockedDevice:
    ip: str
    mac: str
    name: str
    blocked_at: datetime


class BlockManager:
    def __init__(self):
        self._blocked: dict[str, BlockedDevice] = {}

    def is_blocked(self, mac: str) -> bool:
        return mac.lower() in self._blocked

    def list_blocked(self) -> list[BlockedDevice]:
        return list(self._blocked.values())

    def validate_target(self, device, info) -> tuple[bool, str]:
        if device.protected:
            return False, "Protected devices cannot be blocked."

        if device.ip == info.gateway:
            return False, "The network gateway cannot be blocked."

        if device.ip == info.local_ip:
            return False, "This computer cannot be blocked."

        if device.mac.lower() == info.mac.lower():
            return False, "This computer cannot be blocked."

        if device.mac == "unknown":
            return False, "Device does not have a usable MAC address."

        return True, ""

    def block(self, device, info) -> tuple[bool, str]:
        valid, reason = self.validate_target(device, info)

        if not valid:
            return False, reason

        key = device.mac.lower()

        if key in self._blocked:
            return False, "Device is already marked as blocked."

        # ------------------------------------------------------------
        # NETWORK BLOCKING IMPLEMENTATION
        # ------------------------------------------------------------
        #
        # [Insert poison here]
        #
        # ------------------------------------------------------------

        self._blocked[key] = BlockedDevice(
            ip=device.ip,
            mac=device.mac,
            name=device.custom_name or device.name,
            blocked_at=datetime.now(),
        )

        return True, f"{device.custom_name or device.name} marked as blocked."

    def restore(self, mac: str) -> tuple[bool, str]:
        key = mac.lower()

        blocked = self._blocked.get(key)

        if blocked is None:
            return False, "Device is not currently marked as blocked."

        # ------------------------------------------------------------
        # NETWORK RESTORE IMPLEMENTATION
        # ------------------------------------------------------------
        #
        # Insert legitimate restoration operation here.
        #
        # ------------------------------------------------------------

        del self._blocked[key]

        return True, f"{blocked.name} restored."

    def restore_all(self) -> int:
        devices = list(self._blocked.values())

        for device in devices:
            self.restore(device.mac)

        return len(devices)
