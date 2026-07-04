# -*- encoding: utf-8 -*-
"""
keriguard.core.systeming module

Cross-platform WireGuard interface control.

macOS strategy
--------------
Initial bring-up / teardown uses ``sudo wg-quick up/down``.  Hot
reconfiguration uses ``wg-quick strip | sudo wg syncconf`` to apply
updated configs to a running interface without tunnel teardown.
"""

import asyncio
import logging
import os
import platform
import re
import shutil
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

_WG_UAPI_SOCK_DIR = Path("/var/run/wireguard")


# ---------------------------------------------------------------------------
# Resolve WireGuard tool paths once at import time.
#
# On Apple Silicon Macs, Homebrew installs to /opt/homebrew/bin/ which is
# NOT on sudo's secure_path.  Using absolute paths ensures subprocess calls
# (especially those prefixed with "sudo") find the correct binaries.
# ---------------------------------------------------------------------------

def _resolve_utun_name(interface: str) -> str:
    """Resolve a wg-quick alias (e.g. 'wg0') to the real utun device name.

    On macOS, wg-quick writes the real device name to
    ``/var/run/wireguard/<interface>.name``.  The ``wg`` CLI needs the real
    name to find the UAPI socket (``<utun>.sock``).

    The .name file is typically root-owned 600.  Falls back to
    ``sudo wg show interfaces`` (covered by the existing sudoers rule)
    when the file cannot be read; if exactly one WireGuard interface is
    running, that must be ours.

    Returns the real name, or the original interface name unchanged
    (correct on Linux where interface names are used directly).
    """
    name_file = _WG_UAPI_SOCK_DIR / f"{interface}.name"
    try:
        return name_file.read_text().strip()
    except FileNotFoundError:
        return interface
    except PermissionError:
        result = subprocess.run(
            ["sudo", _WG_BIN, "show", "interfaces"],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            ifaces = result.stdout.strip().split()
            if len(ifaces) == 1:
                return ifaces[0]
        return interface

def _resolve_tool(name: str) -> str:
    """Return the absolute path to a CLI tool, or fall back to the bare name."""
    path = shutil.which(name)
    return path if path is not None else name


_WG_BIN = _resolve_tool("wg")
_WG_QUICK_BIN = _resolve_tool("wg-quick")


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
# macOS: wg-quick (bring-up/teardown) + wg syncconf (hot reconfiguration)
# ---------------------------------------------------------------------------

async def _is_wireguard_up(interface: str) -> bool:
    """Return True if the named WireGuard interface is currently running.

    On macOS, wireguard-go names its UAPI socket after the real utun device
    (e.g. ``utun6.sock``) while wg-quick records the mapping in a ``.name``
    file (e.g. ``wg0.name``).

    We check that:
    1. The .name file exists
    2. The corresponding .sock file also exists (guards against stale name
       files left by a crash or unclean teardown)

    If both are present the interface is up.  Otherwise we fall back to
    ``sudo wg show``.
    """
    name_file = _WG_UAPI_SOCK_DIR / f"{interface}.name"
    if name_file.exists():
        # Try to read the real utun name and verify the socket is live
        try:
            real_name = name_file.read_text().strip()
            sock = _WG_UAPI_SOCK_DIR / f"{real_name}.sock"
            if sock.exists():
                _log.debug(
                    f"_is_wireguard_up({interface!r}): name file maps to "
                    f"{real_name!r}, socket exists — interface is up"
                )
                return True
            else:
                _log.debug(
                    f"_is_wireguard_up({interface!r}): name file exists but "
                    f"socket {sock} is missing — stale name file"
                )
        except PermissionError:
            # Running as non-root: can't read .name contents.
            # Fall through to sudo wg show.
            _log.debug(
                f"_is_wireguard_up({interface!r}): name file exists but "
                f"unreadable — falling back to sudo wg show"
            )

    # Fallback: ask the wg tool directly
    proc = await asyncio.create_subprocess_exec(
        "sudo", _WG_BIN, "show", interface,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    is_up = proc.returncode == 0
    if not is_up:
        _log.debug(
            f"_is_wireguard_up({interface!r}) returned False — "
            f"rc={proc.returncode}, stderr={stderr.decode().strip()!r}"
        )
    return is_up


async def _mac_syncconf(interface: str, config_path: str,
                        real_iface: str | None = None) -> None:
    """Apply a config file to a running WireGuard interface without disruption.

    Runs ``sudo wg-quick strip`` to remove Address/DNS/routing directives
    (which only wg-quick understands), then pipes the result into
    ``sudo wg syncconf``.  No tunnel teardown occurs, so existing sessions
    are preserved.

    On macOS, the ``wg`` tool addresses interfaces by their real utun device
    name (e.g. ``utun6``), not the wg-quick alias (``wg0``).  Pass
    ``real_iface`` when already known (e.g. extracted from a wg-quick error
    message); otherwise it is resolved via the ``.name`` file.
    """
    if real_iface is None:
        real_iface = _resolve_utun_name(interface)

    # wg-quick unconditionally checks for root before any subcommand, so
    # 'strip' must also be run via sudo.
    strip = await asyncio.create_subprocess_exec(
        "sudo", _WG_QUICK_BIN, "strip", config_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stripped, strip_err = await strip.communicate()
    if strip.returncode != 0:
        raise WireGuardControlError(
            f"wg-quick strip failed for {config_path!r}: {strip_err.decode().strip()}"
        )

    sync = await asyncio.create_subprocess_exec(
        "sudo", _WG_BIN, "syncconf", real_iface, "/dev/stdin",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, sync_err = await sync.communicate(input=stripped)
    if sync.returncode != 0:
        raise WireGuardControlError(
            f"wg syncconf failed for {interface!r} (device {real_iface}): "
            f"{sync_err.decode().strip()}"
        )


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
            return  # launchd persistence is out of scope for the PoC

        if config_path is None:
            raise WireGuardControlError(
                f"config_path is required for macOS WireGuard control (action={action!r})"
            )

        match action:
            case (WireGuardAction.START
                  | WireGuardAction.RESTART
                  | WireGuardAction.RELOAD
                  | WireGuardAction.RELOAD_OR_RESTART):
                if await _is_wireguard_up(interface):
                    return await _mac_syncconf(interface, config_path)
                proc = await asyncio.create_subprocess_exec(
                    "sudo", _WG_QUICK_BIN, "up", config_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, err = await proc.communicate()
                if proc.returncode != 0:
                    err_str = err.decode().strip()
                    # Interface already up but _is_wireguard_up missed it
                    # (root-owned /var/run/wireguard/ files not visible to user process).
                    # Fall back to hot reconfigure rather than failing.
                    if "already exists" in err_str:
                        # wg-quick reports e.g. "wg0' already exists as `utun4'"
                        # Extract the real utun name so wg syncconf gets the right device.
                        m = re.search(r"already exists as `([^']+)'", err_str)
                        real_iface = m.group(1) if m else None
                        _log.debug(
                            f"wg-quick up: {interface!r} already exists as "
                            f"{real_iface!r} — falling back to syncconf"
                        )
                        return await _mac_syncconf(interface, config_path,
                                                   real_iface=real_iface)
                    raise WireGuardControlError(
                        f"wg-quick up failed for {config_path!r}: {err_str}"
                    )

            case WireGuardAction.STOP | WireGuardAction.DISABLE:
                proc = await asyncio.create_subprocess_exec(
                    "sudo", _WG_QUICK_BIN, "down", config_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, err = await proc.communicate()
                if proc.returncode != 0:
                    raise WireGuardControlError(
                        f"wg-quick down failed for {config_path!r}: {err.decode().strip()}"
                    )

            case _:
                raise WireGuardControlError(
                    f"Unsupported action for macOS: {action!r}"
                )
        return

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


async def reload_or_restart_wireguard(interface: str, config_path: str | None = None) -> object:
    return await control_wireguard(WireGuardAction.RELOAD_OR_RESTART, interface, config_path)


async def enable_wireguard(interface: str, config_path: str | None = None) -> object:
    return await control_wireguard(WireGuardAction.ENABLE, interface, config_path)


async def disable_wireguard(interface: str, config_path: str | None = None) -> object:
    return await control_wireguard(WireGuardAction.DISABLE, interface, config_path)