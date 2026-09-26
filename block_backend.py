#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Blocking backend interface and state management for the modern fork.

The UI selects and validates devices independently from the mechanism that
enforces access control. The enforcement implementation intentionally lives
behind BlockBackend so state/timer code does not depend on a specific backend.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass
class BlockRecord:
    ip: str
    mac: str
    name: str
    started_at: datetime
    ends_at: datetime | None = None

    @property
    def timed(self) -> bool:
        return self.ends_at is not None

    def remaining_seconds(self, now: datetime | None = None) -> int | None:
        if self.ends_at is None:
            return None
        now = now or datetime.now()
        return max(0, int((self.ends_at - now).total_seconds()))


class BlockBackend:
    """Interface for an authorized network access-control backend."""

    def block(self, *, ip: str, mac: str, name: str) -> None:
        print(f"DEBUG block target: ip={ip}, mac={mac}, name={name}")
        def sendPacket(my_mac, gateway_ip, target_ip, target_mac):
            ether = Ether()
            ether.src = my_mac

            arp = ARP()
            arp.psrc = gateway_ip
            arp.hwsrc = my_mac

            arp = arp
            arp.pdst = target_ip
            arp.hwdst = target_mac

            ether = ether
            ether.src = my_mac
            ether.dst = target_mac

            arp.op = 2
        print("DEBUG backend block call completed")
        def broadcastPacket():
            packet = ether / arp
            sendp(x=packet, verbose=False)

    def restore(self, *, ip: str, mac: str) -> None:
        try:
            spoof.sendPacket(defaultGatewayMac, defaultGatewayIP, host[0], host[1])
        except KeyboardInterrupt:
            pass
        except Exception:
            runDebug()
        reArp += 1
        time.sleep(0.2)
        print("{}Re-arped{} target successfully.{}".format(RED, GREEN, END))


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

    def is_blocked(self, mac: str) -> bool:
        return mac.lower() in self._blocked

    def block(
        self,
        device,
        info,
        *,
        duration_minutes: int | None = None,
    ) -> tuple[bool, str]:
        ok, reason = self.validate_target(device, info)
        if not ok:
            return False, reason

        if duration_minutes is not None and duration_minutes <= 0:
            return False, "Duration must be greater than zero minutes."

        key = device.mac.lower()
        if key in self._blocked:
            return False, "Device is already blocked."

        name = device.custom_name or device.name
        try:
            self.backend.block(ip=device.ip, mac=device.mac, name=name)
        except (NotImplementedError, RuntimeError, OSError) as exc:
            return False, str(exc)

        started_at = datetime.now()
        ends_at = None
        if duration_minutes is not None:
            ends_at = started_at + timedelta(minutes=duration_minutes)

        self._blocked[key] = BlockRecord(
            ip=device.ip,
            mac=device.mac,
            name=name,
            started_at=started_at,
            ends_at=ends_at,
        )

        if ends_at is None:
            return True, f"{name} blocked until manually restored."
        return True, f"{name} blocked until {ends_at.strftime('%I:%M:%S %p')}."

    def restore(self, mac: str) -> tuple[bool, str]:
        key = mac.lower()
        record = self._blocked.get(key)
        if record is None:
            return False, "Device is not currently blocked."

        try:
            self.backend.restore(ip=record.ip, mac=record.mac)
        except (NotImplementedError, RuntimeError, OSError) as exc:
            return False, str(exc)

        del self._blocked[key]
        return True, f"{record.name} restored."

    def restore_all(self) -> tuple[int, list[str]]:
        restored = 0
        errors: list[str] = []

        for record in list(self._blocked.values()):
            ok, message = self.restore(record.mac)
            if ok:
                restored += 1
            else:
                errors.append(f"{record.name}: {message}")

        return restored, errors

    def expire_due(self, now: datetime | None = None) -> list[str]:
        """Restore timed blocks whose expiration time has passed."""
        now = now or datetime.now()
        messages: list[str] = []

        due = [
            record
            for record in self._blocked.values()
            if record.ends_at is not None and record.ends_at <= now
        ]

        for record in due:
            ok, message = self.restore(record.mac)
            messages.append(message if ok else f"Restore failed for {record.name}: {message}")

        return messages

    def list_blocked(self) -> list[BlockRecord]:
        return sorted(self._blocked.values(), key=lambda record: record.started_at)
