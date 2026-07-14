# -*- encoding: utf-8 -*-
"""
keriguard.core.systeming module

Cross-platform WireGuard interface control.

macOS strategy
--------------
Control is delegated to KERIGuard Helper (a companion macOS app + Network
Extension — see the ``keriguard-helper`` repo) over a line-delimited JSON
IPC protocol on a local Unix domain socket. The helper owns the actual
WireGuard tunnel via ``NETunnelProviderManager``/WireGuardKit — no sudo, no
``wg-quick``, no utun-device resolution needed on this side.
"""

import asyncio
import json
import logging
import os
import platform
import re
from enum import StrEnum
from pathlib import Path

try:
    from dbus_fast import BusType
    from dbus_fast.aio import MessageBus

    _HAS_DBUS = True
except ImportError:
    _HAS_DBUS = False

_log = logging.getLogger(__name__)

SYSTEMD_SERVICE = "org.freedesktop.systemd1"
SYSTEMD_OBJECT = "/org/freedesktop/systemd1"
SYSTEMD_MANAGER = "org.freedesktop.systemd1.Manager"

WG_IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]+$")

# Must match IPCServer.defaultSocketPath() in keriguard-helper.
_HELPER_SOCKET_PATH = (
    Path.home() / "Library" / "Application Support" / "KERIGuard" / "helper.sock"
)
_HELPER_PROTOCOL_VERSION = 1


class WireGuardAction(StrEnum):
    START = "start"
    STOP = "stop"
    RESTART = "restart"
    RELOAD = "reload"
    RELOAD_OR_RESTART = "reload-or-restart"
    ENABLE = "enable"
    DISABLE = "disable"


class WireGuardControlError(RuntimeError):
    pass


class WireGuardNotApprovedError(WireGuardControlError):
    """Raised when KERIGuard Helper's network extension has not yet been
    approved in System Settings, or the helper is not running at all.

    Callers should treat this as a distinct, actionable status (surfaced
    upstream as ``pending_ne_approval``) rather than a generic failure.
    """

    pass


# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------


def supports_dbus_systemd() -> bool:
    if not _HAS_DBUS:
        return False
    if platform.system() != "Linux":
        return False
    if not os.path.exists("/run/dbus/system_bus_socket"):
        return False
    if not os.path.exists("/run/systemd/system"):
        return False
    return True


def wg_quick_unit(interface: str) -> str:
    if not WG_IFACE_RE.fullmatch(interface):
        raise ValueError(f"Invalid WireGuard interface name: {interface!r}")
    return f"wg-quick@{interface}.service"


# ---------------------------------------------------------------------------
# Linux: systemd / D-Bus
# ---------------------------------------------------------------------------


async def call_systemd(action: WireGuardAction, interface: str) -> object:
    unit = wg_quick_unit(interface)

    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    introspection = await bus.introspect(SYSTEMD_SERVICE, SYSTEMD_OBJECT)
    proxy = bus.get_proxy_object(SYSTEMD_SERVICE, SYSTEMD_OBJECT, introspection)
    manager = proxy.get_interface(SYSTEMD_MANAGER)

    match action:
        case WireGuardAction.START:
            return await manager.call_start_unit(unit, "replace")
        case WireGuardAction.STOP:
            return await manager.call_stop_unit(unit, "replace")
        case WireGuardAction.RESTART:
            return await manager.call_restart_unit(unit, "replace")
        case WireGuardAction.RELOAD:
            return await manager.call_reload_unit(unit, "replace")
        case WireGuardAction.RELOAD_OR_RESTART:
            return await manager.call_reload_or_restart_unit(unit, "replace")
        case WireGuardAction.ENABLE:
            return await manager.call_enable_unit_files([unit], False, False)
        case WireGuardAction.DISABLE:
            return await manager.call_disable_unit_files([unit], False)
        case _:
            raise ValueError(f"Unsupported WireGuard action: {action}")


# ---------------------------------------------------------------------------
# macOS: KERIGuard Helper IPC client
# ---------------------------------------------------------------------------


async def _send_helper_request(
    action: str, interface: str, config: str | None = None
) -> dict:
    """Send a line-delimited JSON request to KERIGuard Helper's Unix domain
    socket IPC server and return the parsed response dict.

    See ``keriguard-helper``'s PLAN.md for the wire protocol. Connection
    failure (socket missing/refused — the helper isn't running) is treated
    the same as an explicit ``not_approved`` response, per that protocol.
    """
    payload = {
        "version": _HELPER_PROTOCOL_VERSION,
        "action": action,
        "interface": interface,
    }
    if config is not None:
        payload["config"] = config

    try:
        reader, writer = await asyncio.open_unix_connection(str(_HELPER_SOCKET_PATH))
    except OSError as e:
        raise WireGuardNotApprovedError(
            f"KERIGuard Helper is not reachable at {_HELPER_SOCKET_PATH}: {e}"
        ) from e

    try:
        writer.write((json.dumps(payload) + "\n").encode())
        await writer.drain()
        line = await reader.readline()
    finally:
        writer.close()

    if not line:
        raise WireGuardControlError(
            "KERIGuard Helper closed the connection without a response"
        )

    try:
        response = json.loads(line)
    except json.JSONDecodeError as e:
        raise WireGuardControlError(
            f"Invalid response from KERIGuard Helper: {line!r}"
        ) from e

    if not response.get("ok"):
        error = response.get("error", "unknown_error")
        if error == "not_approved":
            raise WireGuardNotApprovedError(
                "KERIGuard Helper's network extension has not been approved "
                "in System Settings"
            )
        raise WireGuardControlError(f"KERIGuard Helper returned error: {error}")

    return response


# ---------------------------------------------------------------------------
# Unified control entry point
# ---------------------------------------------------------------------------


async def control_wireguard(
    action: WireGuardAction,
    interface: str,
    config_path: str | None = None,
) -> object:
    if supports_dbus_systemd():
        return await call_systemd(action, interface)

    system = platform.system()

    if system == "Darwin":
        if action == WireGuardAction.ENABLE:
            return  # login item registration + NE approval are owned by KERIGuard Helper

        if config_path is None:
            raise WireGuardControlError(
                f"config_path is required for macOS WireGuard control (action={action!r})"
            )

        match action:
            case (
                WireGuardAction.START
                | WireGuardAction.RESTART
                | WireGuardAction.RELOAD
                | WireGuardAction.RELOAD_OR_RESTART
            ):
                try:
                    config_text = Path(config_path).read_text()
                except OSError as e:
                    raise WireGuardControlError(
                        f"Could not read config file {config_path!r}: {e}"
                    ) from e
                # The helper has no notion of a hot in-place reconfigure — any
                # action beyond an initial START is a full stop-then-start of
                # the NETunnelProviderManager-owned tunnel with the new config.
                ipc_action = "start" if action == WireGuardAction.START else "restart"
                return await _send_helper_request(
                    ipc_action, interface, config=config_text
                )

            case WireGuardAction.STOP | WireGuardAction.DISABLE:
                return await _send_helper_request("stop", interface)

            case _:
                raise WireGuardControlError(f"Unsupported action for macOS: {action!r}")

    if system == "Windows":
        raise WireGuardControlError(
            "Windows placeholder: implement WireGuardNT service control here."
        )

    if system in {"FreeBSD", "OpenBSD", "NetBSD"}:
        raise WireGuardControlError(
            "BSD placeholder: implement rc.d/service or native wg control here."
        )

    raise WireGuardControlError(
        f"Unsupported platform or missing system D-Bus/systemd: {system}"
    )


# ---------------------------------------------------------------------------
# Convenience wrappers
# ---------------------------------------------------------------------------


async def start_wireguard(interface: str, config_path: str | None = None) -> object:
    return await control_wireguard(WireGuardAction.START, interface, config_path)


async def stop_wireguard(interface: str, config_path: str | None = None) -> object:
    return await control_wireguard(WireGuardAction.STOP, interface, config_path)


async def restart_wireguard(interface: str, config_path: str | None = None) -> object:
    return await control_wireguard(WireGuardAction.RESTART, interface, config_path)


async def reload_wireguard(interface: str, config_path: str | None = None) -> object:
    return await control_wireguard(WireGuardAction.RELOAD, interface, config_path)


async def reload_or_restart_wireguard(
    interface: str, config_path: str | None = None
) -> object:
    return await control_wireguard(
        WireGuardAction.RELOAD_OR_RESTART, interface, config_path
    )


async def enable_wireguard(interface: str, config_path: str | None = None) -> object:
    return await control_wireguard(WireGuardAction.ENABLE, interface, config_path)


async def disable_wireguard(interface: str, config_path: str | None = None) -> object:
    return await control_wireguard(WireGuardAction.DISABLE, interface, config_path)
