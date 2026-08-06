# -*- encoding: utf-8 -*-
"""
keriguard.app.sentinel.config

Configuration for Keriguard Sentinel handler.
"""

from dataclasses import dataclass

from keri.app.habbing import Habery, Hab
from keri.vdr.credentialing import Regery

from keriguard.db.basing import KERIGuardBaser


@dataclass
class SentinelHandlerConfig:
    """Configuration for Sentinel event handler."""

    # Sentinel framework settings
    export_dir: str  # Directory containing kel/, tel/, cred/
    sentinel_aid: str | None = None
    poll_interval: float = 2.0  # Polling interval in seconds

    # Wireguard configuration
    config_dir: str = "/etc/wireguard"  # Directory for .conf files

    # KERI settings
    hby: Habery = None
    hab: Hab = None
    rgy: Regery = None
    kgb: KERIGuardBaser = None
    # Handler behavior
    backup_configs: bool = True  # Create .bak files on updates

    # Directory containing the sentinel's Unix socket (LocalWatcherConnector
    # peer-AID resolution retries dial this). Must match whatever
    # `--socket-dir` the sentinel daemon was actually started with -- default
    # ("/tmp") only matches Linux/Debian's unrelocated socket.
    socket_dir: str = "/tmp"
