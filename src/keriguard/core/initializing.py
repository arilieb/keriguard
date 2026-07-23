# -*- encoding: utf-8 -*-
"""
keriguard.core.initializing module

Methods for initializing a KERIGuard instance

"""

import re
from pathlib import Path
from typing import Optional, Dict, Any
from urllib.parse import urlparse

import yaml
import requests
from keri.app import connecting
from keri.core import scheming
from keri.kering import ConfigurationError

# Regex pattern to extract AID/prefix from OOBI URL
# Matches: /oobi/{cid} or /oobi/{cid}/{role} or /oobi/{cid}/{role}/{eid}
OOBI_RE = re.compile(
    r"\A/oobi/(?P<cid>[^/]+)(?:/(?P<role>[^/]+)(?:/(?P<eid>[^/]+))?)?\Z", re.IGNORECASE
)


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


class KeriguardConfig:
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
    def load(cls, config_path: str) -> "KeriguardConfig":
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
