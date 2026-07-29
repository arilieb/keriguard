# -*- encoding: utf-8 -*-
"""
keriguard.core.initializing module

Methods for initializing a KERIGuard instance

"""

import os
import re
from pathlib import Path
from typing import Optional, Dict, Any
from urllib.parse import urlparse

import yaml
import requests
from keri import help
from keri.app import connecting
from keri.core import scheming
from keri.kering import ConfigurationError

# Regex pattern to extract AID/prefix from OOBI URL
# Matches: /oobi/{cid} or /oobi/{cid}/{role} or /oobi/{cid}/{role}/{eid}
OOBI_RE = re.compile(
    r"\A/oobi/(?P<cid>[^/]+)(?:/(?P<role>[^/]+)(?:/(?P<eid>[^/]+))?)?\Z", re.IGNORECASE
)

logger = help.ogler.getLogger()


class KERIGuardConfig:
    """
    Configuration loader and accessor for KERIGuard guardian start command.

    This class reads a YAML configuration file and provides typed access
    to all configuration values needed for running the guardian service.

    Example YAML structure:
        sentinel:
          aid: "EBraKLI-FshC4NeiDnJZMmypYaHAb7kbzlL6tEIT0Cip"
          export_dir: "/var/lib/sentinel/export"
          poll_interval: 2.0

        wireguard:
          config_dir: "/etc/wireguard"

        keri:
          name: "keriguard"
          alias: "keriguard-sentinel"
          base: ""
          data_dir: null
          passcode: null

        logging:
          level: "INFO"
          file: "/var/log/keriguard/guardian.log"

        guardian:
          heartbeat_file: null

    Example:
        config = KERIGuardConfig.load("/etc/keriguard/guardian.yaml")
        print(config.sentinel_aid)
        print(config.poll_interval)
    """

    def __init__(self, data: Dict[str, Any]):
        self._data = data
        self._sentinel = data.get("sentinel", {})
        self._wireguard = data.get("wireguard", {})
        self._keri = data.get("keri", {})
        self._logging = data.get("logging", {})
        self._guardian = data.get("guardian", {})

    @classmethod
    def load(cls, config_path: str) -> "KERIGuardConfig":
        """
        Load configuration from a YAML file.

        Args:
            config_path: Path to the YAML configuration file

        Returns:
            KERIGuardConfig instance with loaded configuration

        Raises:
            FileNotFoundError: If the configuration file doesn't exist
            yaml.YAMLError: If the YAML is malformed
        """
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        with open(path, "r") as f:
            data = yaml.safe_load(f)

        if data is None:
            data = {}

        return cls(data)

    # Sentinel properties
    @property
    def sentinel_aid(self) -> Optional[str]:
        """The AID of the Sentinel to monitor."""
        return self._sentinel.get("aid")

    @property
    def sentinel_export_dir(self) -> Optional[str]:
        """Directory to monitor for KERI events."""
        return self._sentinel.get("export_dir")

    @property
    def poll_interval(self) -> float:
        """Polling interval in seconds (default: 2.0)."""
        return self._sentinel.get("poll_interval", 2.0)

    # WireGuard properties
    @property
    def config_dir(self) -> str:
        """WireGuard config directory (default: /etc/wireguard)."""
        return self._wireguard.get("config_dir", "/etc/wireguard")

    # KERI properties
    @property
    def name(self) -> str:
        """KERI keystore name (default: keriguard)."""
        return self._keri.get("name", "keriguard")

    @property
    def alias(self) -> str:
        """KERI identifier alias (default: keriguard-sentinel)."""
        return self._keri.get("alias", "keriguard-sentinel")

    @property
    def base(self) -> str:
        """KERI keystore base directory (default: empty string)."""
        return self._keri.get("base", "")

    @property
    def data_dir(self) -> Optional[str]:
        """Absolute override for the KERI keystore/db head directory."""
        return self._keri.get("data_dir")

    @property
    def passcode(self) -> Optional[str]:
        """21-character encryption passcode for KERI keystore."""
        return self._keri.get("passcode")

    # Logging properties
    @property
    def loglevel(self) -> str:
        """Log level (default: INFO)."""
        return self._logging.get("level", "INFO")

    @property
    def logfile(self) -> Optional[str]:
        """Path to the log file."""
        return self._logging.get("file")

    @property
    def heartbeat_file(self) -> Optional[str]:
        """Path touched after each poll cycle completes without error."""
        return self._guardian.get("heartbeat_file")


class RegistrarKeriguardConfig:

    def __init__(self, data: Dict[str, Any]):
        self._data = data

    @property
    def aid(self) -> str:
        """The issuer's AID."""
        return self._data.get("aid", "")

    @property
    def oobi(self) -> str:
        """The issuer's OOBI URL."""
        return self._data.get("oobi", "")

    @property
    def ipaddress(self) -> Optional[str]:
        """The registrar's internal Wireguard address."""
        return self._data.get("ipaddress")

    @ipaddress.setter
    def ipaddress(self, value: Optional[str]) -> None:
        """Set the registrar's internal Wireguard address."""
        if value is None:
            self._data.pop("ipaddress", None)
        else:
            self._data["ipaddress"] = value

    @property
    def endpoint(self) -> Optional[str]:
        """The registrar's Wireguard address and port."""
        return self._data.get("endpoint")

    @endpoint.setter
    def endpoint(self, value: Optional[str]) -> None:
        """Set the registrar's Wireguard address and port."""
        if value is None:
            self._data.pop("endpoint", None)
        else:
            self._data["endpoint"] = value


class RegistrarConfig:
    """Configuration for the registrar."""

    def __init__(self, data: Dict[str, Any]):
        self._data = data
        self._keriguard = RegistrarKeriguardConfig(data.get("keriguard", {}))

    @property
    def aid(self) -> str:
        """The registrar's AID."""
        return self._data.get("aid", "")

    @property
    def oobi(self) -> str:
        """The registrar's OOBI URL."""
        return self._data.get("oobi", "")

    @property
    def url(self) -> Optional[str]:
        """The registrar's API endpoint URL."""
        return self._data.get("url")

    @property
    def keriguard(self) -> RegistrarKeriguardConfig:
        """The registrar configuration."""
        return self._keriguard


class IssuerConfig:
    """Configuration for the issuer."""

    def __init__(self, data: Dict[str, Any]):
        self._data = data

    @property
    def aid(self) -> str:
        """The issuer's AID."""
        return self._data.get("aid", "")

    @property
    def oobi(self) -> str:
        """The issuer's OOBI URL."""
        return self._data.get("oobi", "")


class ServerConfig:
    """Configuration for the healthKERI SaaS server (SaaS mode only)."""

    def __init__(self, data: Dict[str, Any]):
        self._data = data

    @property
    def auth_key(self) -> str:
        """Server auth code provisioned via Locksmith."""
        return self._data.get("auth_key", "")


class InitializationConfig:
    """
    Configuration loader and accessor for KERIGuard initialization.

    This class reads a YAML configuration file and provides typed access
    to all configuration values needed for initializing a KERIGuard instance.

    Example:
        config = KeriguardConfig.load("/path/to/keriguard.conf")
        print(config.registrar.aid)
        print(config.registrar.keriguard.oobi)
        print(config.issuer.aid)
    """

    def __init__(self, data: Dict[str, Any]):
        self._data = data
        self._registrar = RegistrarConfig(data.get("registrar", {}))
        self._issuer = IssuerConfig(data.get("issuer", {}))
        server_data = data.get("server")
        self._server = ServerConfig(server_data) if server_data else None

    @classmethod
    def load(cls, config_path: str) -> "InitializationConfig":
        """
        Load configuration from a YAML file.

        Args:
            config_path: Path to the YAML configuration file

        Returns:
            KeriguardConfig instance with loaded configuration

        Raises:
            FileNotFoundError: If the configuration file doesn't exist
            yaml.YAMLError: If the YAML is malformed
        """
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        with open(path, "r") as f:
            data = yaml.safe_load(f)

        if data is None:
            data = {}

        instance = cls(data)
        if not instance.local and (instance.server is None or instance.server.auth_key is None):  # type: ignore
            raise ConfigurationError("Server configuration is missing or incomplete")

        return instance

    @property
    def local(self) -> bool:
        """True for local mode (self-hosted registrar); False for SaaS mode (hkweb)."""
        return self._data.get("local", True)

    @property
    def server(self) -> Optional["ServerConfig"]:
        """SaaS server configuration (only present when local=False)."""
        return self._server

    @property
    def registrar(self) -> RegistrarConfig:
        """The registrar configuration."""
        return self._registrar

    @property
    def issuer(self) -> IssuerConfig:
        """The issuer configuration."""
        return self._issuer


def load_schema(hby, schema_oobi: str, schema_said: str):
    response = requests.get(schema_oobi)
    schemer = scheming.Schemer(raw=bytearray(response.content))
    if schemer.said == schema_said:
        hby.db.schema.pin(keys=(schemer.said,), val=schemer)
        return True

    return False


def load_oobi(hby, oobi: str, alias: str):
    org = connecting.Organizer(hby=hby)
    purl = urlparse(oobi)
    match = OOBI_RE.match(purl.path)
    if not match:
        raise ValueError(f"Invalid OOBI URL {oobi}")

    aid = match.group("cid")

    # If the AID is already in the local key-event database, skip the network
    # call.  The vault may have resolved this OOBI in a previous session while
    # the witness has since been restarted with empty state (e.g. after a
    # clean-slate wipe of /usr/local/var/keri/).  The locally cached key state
    # is authoritative; the sentinel will refresh it via witness queries later.
    if aid in hby.kevers:
        org.update(pre=aid, data=dict(alias=alias, oobi=oobi))
        return aid

    response = requests.get(oobi)
    response.raise_for_status()

    hby.psr.parse(ims=response.content)
    if aid not in hby.kevers:
        raise ValueError(f"Invalid OOBI URL {oobi} for {aid}")

    hby.kvy.processEscrows()
    org.update(pre=aid, data=dict(alias=alias, oobi=oobi))

    return aid


def generate_guardian_config(
    sentinel_aid: str,
    sentinel_export_dir: str,
    poll_interval: float = 2.0,
    config_dir: str = "/etc/wireguard",
    name: str = "keriguard",
    alias: str = "keriguard-sentinel",
    base: str = "",
    data_dir: Optional[str] = None,
    passcode: Optional[str] = None,
    loglevel: str = "INFO",
    logfile: Optional[str] = None,
    heartbeat_file: Optional[str] = None,
) -> dict:
    """
    Generate a guardian configuration dictionary.

    Args:
        sentinel_aid: AID of the Sentinel to monitor
        sentinel_export_dir: Directory to monitor for KERI events
        poll_interval: Polling interval in seconds
        config_dir: WireGuard config directory
        name: KERI keystore name
        alias: KERI identifier alias
        base: KERI keystore base directory
        data_dir: Absolute override for the KERI keystore/db head directory
        passcode: 21-character encryption passcode
        loglevel: Log level
        logfile: Path to log file
        heartbeat_file: Path touched after each poll cycle completes without error

    Returns:
        dict: Guardian configuration structure
    """
    config = {
        "sentinel": {
            "aid": sentinel_aid,
            "export_dir": sentinel_export_dir,
            "poll_interval": poll_interval,
        },
        "wireguard": {
            "config_dir": config_dir,
        },
        "keri": {
            "name": name,
            "alias": alias,
            "base": base,
        },
        "logging": {
            "level": loglevel,
        },
    }

    # Only include optional values if they're set
    if data_dir:
        config["keri"]["data_dir"] = data_dir

    if passcode:
        config["keri"]["passcode"] = passcode

    if logfile:
        config["logging"]["file"] = logfile

    if heartbeat_file:
        config["guardian"] = {"heartbeat_file": heartbeat_file}

    return config


def save_guardian_config(config: dict, path: str) -> None:
    """
    Save guardian configuration to a YAML file.

    Args:
        config: Guardian configuration dictionary
        path: Path to save the configuration file
    """
    # Ensure the parent directory exists
    config_path = Path(path)
    config_path.parent.mkdir(parents=True, exist_ok=True)

    # Save the configuration
    with open(config_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    # Set appropriate permissions (readable by owner and group)
    os.chmod(config_path, 0o640)

    logger.info(f"Guardian configuration saved to {path}")
