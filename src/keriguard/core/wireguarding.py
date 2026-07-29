# -*- encoding: utf-8 -*-
"""
keriguard.core.wireguarding module

Wireguard configuration management with KERI integration.
"""

import pysodium
import shutil
from keri import help
from keri.core.signing import Signer
from dataclasses import dataclass, field
from typing import Optional, List, Tuple
from pathlib import Path
from ipaddress import ip_address, ip_network
import base64
import re
import os
import datetime
from io import StringIO

logger = help.ogler.getLogger()


class Schema:
    INTERFACE_SCHEMA = "EJhuwoliTRahBQTHyfvIROkMh6_goGAqduSsNvSD-Wco"
    CONNECTION_SCHEMA = "EHaADfqxCtpXyu1h-9W6Q5xBiA53caj9uv34OO-vdLIf"
    TRUSTNET_SCHEMA = "EDEtWN9L3Eguugoa9AyUC6L_4mCQqVvlVEbKAKPoBCwy"


SCHEMA_OOBIS = {
    Schema.INTERFACE_SCHEMA: f"https://healthkeri-schema.sfo3.digitaloceanspaces.com/oobi/{Schema.INTERFACE_SCHEMA}",
    Schema.CONNECTION_SCHEMA: f"https://healthkeri-schema.sfo3.digitaloceanspaces.com/oobi/{Schema.CONNECTION_SCHEMA}",
    Schema.TRUSTNET_SCHEMA: f"https://healthkeri-schema.sfo3.digitaloceanspaces.com/oobi/{Schema.TRUSTNET_SCHEMA}",
}


# ============================================================================
# Exceptions
# ============================================================================


class WireguardError(Exception):
    """Base exception for Wireguard configuration errors."""

    pass


class KeyGenerationError(WireguardError):
    """Exception raised when key generation fails."""

    pass


class PeerAIDMissingError(WireguardError):
    """Exception raised when peer AID is missing in configuration."""

    pass


class PeerResolutionPendingError(WireguardError):
    """Raised when peer AID resolution has been queued but is not yet complete.

    The caller should treat this as a transient failure and retry later.
    """

    pass


class ValidationError(WireguardError):
    """Exception raised when configuration validation fails."""

    pass


class ConfigParseError(WireguardError):
    """Exception raised when parsing a configuration file fails."""

    pass


class ConfigWriteError(WireguardError):
    """Exception raised when writing a configuration file fails."""

    pass


# ============================================================================
# KERI Integration
# ============================================================================


class KERIKeyGenerator:
    """Generate Wireguard keys with KERI identity tracking."""

    def __init__(self, hab):
        self.hab = hab

    def generate_keypair(self) -> Tuple[str, str, Signer]:
        """
        Generate a Wireguard keypair with KERI Signer for identity tracking.

        Returns:
            Tuple of (private_key_b64, public_key_b64, keri_signer)

        Raises:
            KeyGenerationError: If key generation fails
        """
        try:
            # Generate KERI Signer for identity tracking
            keri_signer = self.hab.ks.pris.get(
                self.hab.kever.verfers[0].qb64, decrypter=self.hab.mgr.decrypter
            )

            sigkey = (
                keri_signer.raw + keri_signer.verfer.raw
            )  # sigkey is raw seed + raw verkey
            private_key_bytes = pysodium.crypto_sign_sk_to_box_sk(
                sigkey
            )  # raw private encrypt key
            public_key_bytes = pysodium.crypto_scalarmult_curve25519_base(
                private_key_bytes
            )

            # Encode as base64
            private_key_b64 = base64.b64encode(private_key_bytes).decode("ascii")
            public_key_b64 = base64.b64encode(public_key_bytes).decode("ascii")

            logger.info(
                f"Generated Wireguard keypair with KERI signer {keri_signer.qb64}"
            )

            return private_key_b64, public_key_b64, keri_signer

        except Exception as e:
            logger.error(f"Failed to generate keypair: {e}")
            raise KeyGenerationError(f"Key generation failed: {e}") from e

    def generate_peer_key(self, aid: str):
        try:
            kever = self.hab.kevers[aid]
            public_key_bytes = pysodium.crypto_sign_pk_to_box_pk(kever.verfers[0].raw)

            public_key_b64 = base64.b64encode(public_key_bytes).decode("ascii")

            return public_key_b64

        except KeyError:
            logger.error(f"KERI AID {aid} not found in kevers")
            raise PeerAIDMissingError(f"KERI AID not found: {aid}")
        except Exception as e:
            logger.error(f"Failed to generate keypair: {e}")
            raise KeyGenerationError(f"Key generation failed: {e}") from e

    @staticmethod
    def generate_preshared_key() -> str:
        """
        Generate a preshared key for Wireguard.

        Returns:
            Base64-encoded 32-byte preshared key

        Raises:
            KeyGenerationError: If key generation fails
        """
        try:
            psk_bytes = os.urandom(32)
            psk_b64 = base64.b64encode(psk_bytes).decode("ascii")
            logger.info("Generated preshared key")
            return psk_b64
        except Exception as e:
            logger.error(f"Failed to generate preshared key: {e}")
            raise KeyGenerationError(f"Preshared key generation failed: {e}") from e

    @staticmethod
    def _derive_public_key(private_key_b64: str) -> str:
        """
        Derive public key from private key.

        Args:
            private_key_b64: Base64-encoded private key

        Returns:
            Base64-encoded public key

        Raises:
            KeyGenerationError: If key derivation fails
        """
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import (
                X25519PrivateKey,
            )

            # Decode private key
            private_key_bytes = base64.b64decode(private_key_b64)

            # Load private key object
            private_key_obj = X25519PrivateKey.from_private_bytes(private_key_bytes)

            # Derive public key
            public_key_obj = private_key_obj.public_key()
            public_key_bytes = public_key_obj.public_bytes_raw()

            # Encode as base64
            public_key_b64 = base64.b64encode(public_key_bytes).decode("ascii")

            return public_key_b64

        except Exception as e:
            logger.error(f"Failed to derive public key: {e}")
            raise KeyGenerationError(f"Public key derivation failed: {e}") from e


# ============================================================================
# Validation
# ============================================================================


class InterfaceValidator:
    """Validator for Wireguard interface configuration."""

    @staticmethod
    def validate_private_key(private_key: str) -> None:
        """Validate private key format."""
        if not private_key:
            raise ValidationError("Private key is required")

        try:
            key_bytes = base64.b64decode(private_key)
            if len(key_bytes) != 32:
                raise ValidationError(
                    f"Private key must be 32 bytes, got {len(key_bytes)}"
                )
            if key_bytes == b"\x00" * 32:
                raise ValidationError("Private key cannot be all zeros")
        except Exception as e:
            if isinstance(e, ValidationError):
                raise
            raise ValidationError(f"Invalid private key format: {e}") from e

    @staticmethod
    def validate_address(address: str) -> None:
        """Validate IP address in CIDR notation."""
        try:
            ip_network(address, strict=False)
            # Ensure it has a prefix length
            if "/" not in address:
                raise ValidationError(f"Address must include CIDR prefix: {address}")
        except ValueError as e:
            raise ValidationError(f"Invalid address format: {e}") from e

    @staticmethod
    def validate_addresses(addresses: List[str]) -> None:
        """Validate list of addresses."""
        if not addresses:
            raise ValidationError("At least one address is required")
        for addr in addresses:
            InterfaceValidator.validate_address(addr)

    @staticmethod
    def validate_listen_port(port: Optional[int]) -> None:
        """Validate listen port."""
        if port is not None:
            if not isinstance(port, int):
                raise ValidationError(
                    f"Listen port must be an integer, got {type(port).__name__}"
                )
            if port < 1 or port > 65535:
                raise ValidationError(
                    f"Listen port must be between 1 and 65535, got {port}"
                )

    @staticmethod
    def validate_dns(dns_list: Optional[List[str]]) -> None:
        """Validate DNS servers."""
        if dns_list is None:
            return

        for dns in dns_list:
            # Try to parse as IP address
            try:
                ip_address(dns)
            except ValueError:
                # If not an IP, validate as hostname
                if not re.match(
                    r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,"
                    r"61}[a-zA-Z0-9])?)*$",
                    dns,
                ):
                    raise ValidationError(f"Invalid DNS server format: {dns}")

    @staticmethod
    def validate_mtu(mtu: Optional[int]) -> None:
        """Validate MTU."""
        if mtu is not None:
            if not isinstance(mtu, int):
                raise ValidationError(
                    f"MTU must be an integer, got {type(mtu).__name__}"
                )
            if mtu < 1280 or mtu > 9000:
                raise ValidationError(f"MTU must be between 1280 and 9000, got {mtu}")


class PeerValidator:
    """Validator for Wireguard peer configuration."""

    @staticmethod
    def validate_public_key(public_key: str) -> None:
        """Validate public key format."""
        if not public_key:
            raise ValidationError("Public key is required")

        try:
            key_bytes = base64.b64decode(public_key)
            if len(key_bytes) != 32:
                raise ValidationError(
                    f"Public key must be 32 bytes, got {len(key_bytes)}"
                )
        except Exception as e:
            if isinstance(e, ValidationError):
                raise
            raise ValidationError(f"Invalid public key format: {e}") from e

    @staticmethod
    def validate_allowed_ips(allowed_ips: List[str]) -> None:
        """Validate allowed IPs."""
        if not allowed_ips:
            raise ValidationError("At least one allowed IP is required")

        for allowed_ip in allowed_ips:
            try:
                ip_network(allowed_ip, strict=False)
            except ValueError as e:
                raise ValidationError(f"Invalid allowed IP format: {e}") from e

    @staticmethod
    def validate_endpoint(endpoint: Optional[str]) -> None:
        """Validate endpoint format."""
        if endpoint is None:
            return

        # Match host:port or [IPv6]:port
        ipv6_pattern = r"^\[([0-9a-fA-F:]+)\]:(\d+)$"
        ipv4_pattern = r"^([a-zA-Z0-9.-]+):(\d+)$"

        match = re.match(ipv6_pattern, endpoint)
        if not match:
            match = re.match(ipv4_pattern, endpoint)

        if not match:
            raise ValidationError(
                f"Invalid endpoint format (expected host:port or [IPv6]:port): {endpoint}"
            )

        # Validate port
        port = int(match.group(2))
        if port < 1 or port > 65535:
            raise ValidationError(
                f"Endpoint port must be between 1 and 65535, got {port}"
            )

    @staticmethod
    def validate_persistent_keepalive(keepalive: Optional[int]) -> None:
        """Validate persistent keepalive."""
        if keepalive is not None:
            if not isinstance(keepalive, int):
                raise ValidationError(
                    f"Persistent keepalive must be an integer, got {type(keepalive).__name__}"
                )
            if keepalive < 1 or keepalive > 300:
                raise ValidationError(
                    f"Persistent keepalive must be between 1 and 300, got {keepalive}"
                )

    @staticmethod
    def validate_preshared_key(preshared_key: Optional[str]) -> None:
        """Validate preshared key format."""
        if preshared_key is None:
            return

        try:
            key_bytes = base64.b64decode(preshared_key)
            if len(key_bytes) != 32:
                raise ValidationError(
                    f"Preshared key must be 32 bytes, got {len(key_bytes)}"
                )
        except Exception as e:
            if isinstance(e, ValidationError):
                raise
            raise ValidationError(f"Invalid preshared key format: {e}") from e


class ConfigValidator:
    """Validator for complete Wireguard configuration."""

    @staticmethod
    def validate_config(config: "WireguardConfig") -> None:
        """
        Validate complete configuration including conflict detection.

        Args:
            config: Configuration to validate

        Raises:
            ValidationError: If validation fails
        """
        # Validate interface (already done in __post_init__, but explicit check)
        if config.interface is None:
            raise ValidationError("Configuration must have an interface")

        # Check for duplicate peer public keys
        public_keys = set()
        for peer in config.peers:
            if peer.public_key in public_keys:
                raise ValidationError(f"Duplicate peer public key: {peer.public_key}")
            public_keys.add(peer.public_key)

        # Check for overlapping allowed IPs (warning only)
        ConfigValidator._check_overlapping_allowed_ips(config.peers)

        # Check for conflicts between interface and peer addresses
        ConfigValidator._check_address_conflicts(config)

    @staticmethod
    def _check_overlapping_allowed_ips(peers: List["WireguardPeer"]) -> None:
        """Check for overlapping allowed IPs between peers."""
        networks = []
        for peer in peers:
            for allowed_ip in peer.allowed_ips:
                network = ip_network(allowed_ip, strict=False)
                networks.append((network, peer.public_key, allowed_ip))

        # Check for overlaps
        for i, (net1, key1, ip1) in enumerate(networks):
            for net2, key2, ip2 in networks[i + 1 :]:
                if net1.overlaps(net2):
                    logger.warning(
                        f"Overlapping allowed IPs: {ip1} (peer {key1[:8]}...) and {ip2} (peer {key2[:8]}...)"
                    )

    @staticmethod
    def _check_address_conflicts(config: "WireguardConfig") -> None:
        """Check for conflicts between interface and peer addresses."""
        # Get interface networks
        interface_networks = []
        for addr in config.interface.address:
            network = ip_network(addr, strict=False)
            interface_networks.append(network)

        # Check peer allowed IPs against interface addresses
        for peer in config.peers:
            for allowed_ip in peer.allowed_ips:
                peer_network = ip_network(allowed_ip, strict=False)
                for interface_network in interface_networks:
                    # Check if peer network could route back to interface
                    if peer_network.overlaps(interface_network):
                        logger.debug(
                            f"Peer allowed IP {allowed_ip} overlaps with interface address {interface_network}"
                        )


# ============================================================================
# Data Models
# ============================================================================


@dataclass
class WireguardInterface:
    """Wireguard interface configuration."""

    # Required fields
    private_key: str
    address: List[str]

    # Optional fields
    listen_port: Optional[int] = None
    dns: Optional[List[str]] = None
    mtu: Optional[int] = None
    table: Optional[str] = None
    pre_up: Optional[str] = None
    post_up: Optional[str] = None
    pre_down: Optional[str] = None
    post_down: Optional[str] = None

    # Metadata (written to .conf as comments)
    keri_aid_qb64: Optional[str] = None

    def __post_init__(self):
        """Validate interface configuration."""
        InterfaceValidator.validate_private_key(self.private_key)
        InterfaceValidator.validate_addresses(self.address)
        InterfaceValidator.validate_listen_port(self.listen_port)
        InterfaceValidator.validate_dns(self.dns)
        InterfaceValidator.validate_mtu(self.mtu)


@dataclass
class WireguardPeer:
    """Wireguard peer configuration."""

    # Required fields
    public_key: str
    allowed_ips: List[str]

    # Optional fields
    endpoint: Optional[str] = None
    persistent_keepalive: Optional[int] = None
    preshared_key: Optional[str] = None

    # Metadata (not written to .conf)
    keri_aid_qb64: Optional[str] = None
    peer_name: Optional[str] = None

    def __post_init__(self):
        """Validate peer configuration."""
        PeerValidator.validate_public_key(self.public_key)
        PeerValidator.validate_allowed_ips(self.allowed_ips)
        PeerValidator.validate_endpoint(self.endpoint)
        PeerValidator.validate_persistent_keepalive(self.persistent_keepalive)
        PeerValidator.validate_preshared_key(self.preshared_key)


@dataclass
class WireguardConfig:
    """Complete Wireguard configuration."""

    interface: WireguardInterface
    peers: List[WireguardPeer] = field(default_factory=list)

    # Metadata
    config_name: Optional[str] = None
    description: Optional[str] = None
    created_at: Optional[datetime.datetime] = None
    modified_at: Optional[datetime.datetime] = None

    def __post_init__(self):
        """Initialize timestamps if not set."""
        if self.created_at is None:
            self.created_at = datetime.datetime.now(datetime.UTC)
        if self.modified_at is None:
            self.modified_at = self.created_at

    def add_peer(self, peer: WireguardPeer) -> None:
        """Add a peer to the configuration."""
        # Check for duplicate public key
        for existing_peer in self.peers:
            if existing_peer.public_key == peer.public_key:
                raise ValidationError(
                    f"Peer with public key {peer.public_key} already exists"
                )

        self.peers.append(peer)
        self.modified_at = datetime.datetime.now(datetime.UTC)
        logger.info(f"Added peer {peer.public_key[:8]}... to configuration")

    def remove_peer(self, public_key: str) -> bool:
        """Remove a peer by public key."""
        for i, peer in enumerate(self.peers):
            if peer.public_key == public_key:
                self.peers.pop(i)
                self.modified_at = datetime.datetime.now(datetime.UTC)
                logger.info(f"Removed peer {public_key[:8]}... from configuration")
                return True
        return False

    def remove_peer_by_aid(self, aid: str) -> bool:
        """Remove a peer by public key."""
        for i, peer in enumerate(self.peers):
            if peer.keri_aid_qb64 == aid:
                self.peers.pop(i)
                self.modified_at = datetime.datetime.now(datetime.UTC)
                logger.info(f"Removed peer {aid[:8]}... from configuration")
                return True
        return False

    def get_peer(self, public_key: str) -> Optional[WireguardPeer]:
        """Get a peer by public key."""
        for peer in self.peers:
            if peer.public_key == public_key:
                return peer
        return None

    def get_peer_by_aid(self, aid: str) -> Optional[WireguardPeer]:
        """Get a peer by KERI AID."""
        for peer in self.peers:
            if peer.keri_aid_qb64 == aid:
                return peer
        return None


# ============================================================================
# File I/O
# ============================================================================


class WireguardConfigParser:
    """Parser for Wireguard configuration files."""

    @staticmethod
    def parse_file(path: Path) -> WireguardConfig:
        """
        Parse a Wireguard configuration file.

        Args:
            path: Path to configuration file

        Returns:
            Parsed WireguardConfig

        Raises:
            ConfigParseError: If parsing fails
        """
        try:
            with open(path, "r") as f:
                content = f.read()

            config = WireguardConfigParser.parse_stream(StringIO(content))
            config.config_name = path.stem

            logger.info(f"Parsed configuration from {path}")
            return config

        except Exception as e:
            if isinstance(e, (ConfigParseError, ValidationError)):
                raise
            logger.error(f"Failed to parse configuration file {path}: {e}")
            raise ConfigParseError(f"Failed to parse {path}: {e}") from e

    @staticmethod
    def parse_stream(stream: StringIO) -> WireguardConfig:
        """
        Parse a Wireguard configuration from a stream.

        Args:
            stream: Text stream containing configuration

        Returns:
            Parsed WireguardConfig

        Raises:
            ConfigParseError: If parsing fails
        """
        try:
            lines = stream.readlines()

            interface_data = {}
            peers_data = []
            current_section = None
            current_peer = None

            for line_num, line in enumerate(lines, 1):
                line = line.strip()

                # Skip empty lines
                if not line:
                    continue

                # Handle metadata comments (for peers)
                if line.startswith("#"):
                    # Extract metadata from comments like "# Name: value" or "# KERI AID: value"
                    if current_section == "interface":
                        if line.startswith("# KERI AID:"):
                            keri_aid = line.split(":", 1)[1].strip()
                            interface_data["keri_aid_qb64"] = keri_aid

                    elif current_section == "peer" and current_peer is not None:
                        if line.startswith("# Name:"):
                            peer_name = line.split(":", 1)[1].strip()
                            current_peer["peer_name"] = peer_name
                        elif line.startswith("# KERI AID:"):
                            keri_aid = line.split(":", 1)[1].strip()
                            current_peer["keri_aid_qb64"] = keri_aid
                    # Skip all other comments
                    continue

                # Section headers
                if line.startswith("[") and line.endswith("]"):
                    section = line[1:-1].strip()

                    if section == "Interface":
                        current_section = "interface"
                        current_peer = None
                    elif section == "Peer":
                        current_section = "peer"
                        if current_peer is not None:
                            peers_data.append(current_peer)
                        current_peer = {}
                    else:
                        raise ConfigParseError(
                            f"Unknown section [{section}] at line {line_num}"
                        )
                    continue

                # Key-value pairs
                if "=" not in line:
                    raise ConfigParseError(
                        f"Invalid line format at line {line_num}: {line}"
                    )

                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()

                # Convert PascalCase to snake_case
                key_snake = WireguardConfigParser._to_snake_case(key)

                # Parse value (handle comma-separated lists)
                if key_snake in ["address", "allowed_ips", "dns"]:
                    parsed_value = [v.strip() for v in value.split(",")]
                elif key_snake in ["listen_port", "mtu", "persistent_keepalive"]:
                    parsed_value = int(value)
                else:
                    parsed_value = value

                # Store in appropriate section
                if current_section == "interface":
                    interface_data[key_snake] = parsed_value
                elif current_section == "peer":
                    current_peer[key_snake] = parsed_value

            # Add final peer if exists
            if current_peer is not None:
                peers_data.append(current_peer)

            # Validate required fields
            if not interface_data:
                raise ConfigParseError("Configuration must have an [Interface] section")

            if "private_key" not in interface_data:
                raise ConfigParseError("[Interface] section missing PrivateKey")

            if "address" not in interface_data:
                raise ConfigParseError("[Interface] section missing Address")

            # Create interface object
            interface = WireguardInterface(
                private_key=interface_data.pop("private_key"),
                address=interface_data.pop("address"),
                listen_port=interface_data.pop("listen_port", None),
                dns=interface_data.pop("dns", None),
                mtu=interface_data.pop("mtu", None),
                table=interface_data.pop("table", None),
                pre_up=interface_data.pop("pre_up", None),
                post_up=interface_data.pop("post_up", None),
                pre_down=interface_data.pop("pre_down", None),
                post_down=interface_data.pop("post_down", None),
                keri_aid_qb64=interface_data.pop("keri_aid_qb64", None),
            )

            # Create peer objects
            peers = []
            for peer_data in peers_data:
                if "public_key" not in peer_data:
                    raise ConfigParseError("[Peer] section missing PublicKey")

                if "allowed_ips" not in peer_data:
                    raise ConfigParseError("[Peer] section missing AllowedIPs")

                peer = WireguardPeer(
                    public_key=peer_data.pop("public_key"),
                    allowed_ips=peer_data.pop("allowed_ips"),
                    endpoint=peer_data.pop("endpoint", None),
                    persistent_keepalive=peer_data.pop("persistent_keepalive", None),
                    preshared_key=peer_data.pop("preshared_key", None),
                    peer_name=peer_data.pop("peer_name", None),
                    keri_aid_qb64=peer_data.pop("keri_aid_qb64", None),
                )
                peers.append(peer)

            # Create config
            config = WireguardConfig(interface=interface, peers=peers)

            return config

        except Exception as e:
            if isinstance(e, (ConfigParseError, ValidationError)):
                raise
            logger.error(f"Failed to parse configuration stream: {e}")
            raise ConfigParseError(f"Failed to parse configuration: {e}") from e

    @staticmethod
    def _to_snake_case(name: str) -> str:
        """Convert PascalCase to snake_case."""
        # Handle special case for IPs (AllowedIPs -> allowed_ips)
        name = name.replace("IPs", "Ips")

        # Insert underscore before uppercase letters
        s1 = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
        s2 = re.sub("([a-z0-9])([A-Z])", r"\1_\2", s1)
        return s2.lower()


class WireguardConfigWriter:
    """Writer for Wireguard configuration files."""

    @staticmethod
    def write_file(config: WireguardConfig, path: Path) -> None:
        """
        Write a Wireguard configuration to a file.

        Args:
            config: Configuration to write
            path: Path to write to

        Raises:
            ConfigWriteError: If writing fails
        """
        try:
            # Ensure parent directory exists
            path.parent.mkdir(parents=True, exist_ok=True)

            # Generate configuration text
            content = WireguardConfigWriter.write_stream(config)

            # Write to file
            with open(path, "w") as f:
                f.write(content)

            logger.info(f"Wrote configuration to {path}")

        except Exception as e:
            if isinstance(e, ConfigWriteError):
                raise
            logger.error(f"Failed to write configuration to {path}: {e}")
            raise ConfigWriteError(f"Failed to write {path}: {e}") from e

    @staticmethod
    def write_stream(config: WireguardConfig) -> str:
        """
        Write a Wireguard configuration to a string.

        Args:
            config: Configuration to write

        Returns:
            Configuration as string

        Raises:
            ConfigWriteError: If writing fails
        """
        try:
            lines = []

            # Write metadata as comments
            if config.config_name:
                lines.append(f"# Configuration: {config.config_name}")
            if config.description:
                lines.append(f"# Description: {config.description}")
            if config.created_at:
                lines.append(f"# Created: {config.created_at.isoformat()}")
            if config.modified_at:
                lines.append(f"# Modified: {config.modified_at.isoformat()}")

            if lines:
                lines.append("")

            # Write [Interface] section
            lines.append("[Interface]")
            if config.interface.keri_aid_qb64:
                lines.append(f"# KERI AID: {config.interface.keri_aid_qb64}")

            lines.append(f"PrivateKey = {config.interface.private_key}")
            lines.append(f"Address = {', '.join(config.interface.address)}")

            if config.interface.listen_port is not None:
                lines.append(f"ListenPort = {config.interface.listen_port}")

            if config.interface.dns:
                lines.append(f"DNS = {', '.join(config.interface.dns)}")

            if config.interface.mtu is not None:
                lines.append(f"MTU = {config.interface.mtu}")

            if config.interface.table is not None:
                lines.append(f"Table = {config.interface.table}")

            if config.interface.pre_up:
                lines.append(f"PreUp = {config.interface.pre_up}")

            if config.interface.post_up:
                lines.append(f"PostUp = {config.interface.post_up}")

            if config.interface.pre_down:
                lines.append(f"PreDown = {config.interface.pre_down}")

            if config.interface.post_down:
                lines.append(f"PostDown = {config.interface.post_down}")

            # Write [Peer] sections
            for peer in config.peers:
                lines.append("")
                lines.append("[Peer]")

                if peer.peer_name:
                    lines.append(f"# Name: {peer.peer_name}")
                if peer.keri_aid_qb64:
                    lines.append(f"# KERI AID: {peer.keri_aid_qb64}")

                lines.append(f"PublicKey = {peer.public_key}")
                lines.append(f"AllowedIPs = {', '.join(peer.allowed_ips)}")

                if peer.endpoint:
                    lines.append(f"Endpoint = {peer.endpoint}")

                if peer.persistent_keepalive is not None:
                    lines.append(f"PersistentKeepalive = {peer.persistent_keepalive}")

                if peer.preshared_key:
                    lines.append(f"PresharedKey = {peer.preshared_key}")

            # Join with newlines and add final newline
            content = "\n".join(lines) + "\n"

            return content

        except Exception as e:
            logger.error(f"Failed to write configuration stream: {e}")
            raise ConfigWriteError(f"Failed to write configuration: {e}") from e


# ============================================================================
# Main API
# ============================================================================


class WireguardConfigManager:
    """Main API facade for Wireguard configuration management."""

    def __init__(self, hab):
        """Initialize the configuration manager."""
        self.hab = hab
        self.key_generator = KERIKeyGenerator(hab=self.hab)

    def generate_config(
        self,
        address: List[str],
        listen_port: Optional[int] = None,
        dns: Optional[List[str]] = None,
        mtu: Optional[int] = None,
        table: Optional[str] = None,
        config_name: Optional[str] = None,
        description: Optional[str] = None,
    ) -> WireguardConfig:
        """
        Generate a new Wireguard configuration with KERI-tracked keys.

        Args:
            address: List of interface addresses in CIDR notation
            listen_port: Optional listen port
            dns: Optional list of DNS servers
            mtu: Optional MTU
            table: Optional routing table
            config_name: Optional configuration name
            description: Optional description

        Returns:
            New WireguardConfig

        Raises:
            KeyGenerationError: If key generation fails
            ValidationError: If validation fails
        """
        logger.info("Generating new Wireguard configuration")

        # Generate keypair with KERI tracking
        private_key, public_key, keri_signer = self.key_generator.generate_keypair()

        # Create interface
        interface = WireguardInterface(
            private_key=private_key,
            address=address if isinstance(address, list) else [address],  # type: ignore
            listen_port=listen_port,
            dns=dns,
            mtu=mtu,
            table=table,
            keri_aid_qb64=self.hab.pre,
        )

        # Create config
        config = WireguardConfig(
            interface=interface,
            peers=[],
            config_name=config_name,
            description=description,
            created_at=datetime.datetime.now(datetime.UTC),
            modified_at=datetime.datetime.now(datetime.UTC),
        )

        logger.info(f"Generated configuration with KERI signer {keri_signer.qb64}")

        return config

    def add_peer_to_config(
        self,
        config: WireguardConfig,
        allowed_ips: List[str],
        endpoint: Optional[str] = None,
        persistent_keepalive: Optional[int] = None,
        public_key: Optional[str] = None,
        preshared_key: Optional[str] = None,
        peer_name: Optional[str] = None,
        keri_aid: Optional[str] = None,
    ) -> WireguardPeer:
        """
        Add a peer to the configuration.

        Args:
            config: Configuration to add peer to
            allowed_ips: List of allowed IPs in CIDR notation
            endpoint: Optional endpoint (host:port)
            persistent_keepalive: Optional keepalive interval
            public_key: Optional public key (if not provided, uses keri_aid)
            keri_aid: Optional KERI AID for key generation (if not provided, uses public_key)
            preshared_key: Optional preshared key
            peer_name: Optional peer name

        Returns:
            Created WireguardPeer

        Raises:
            KeyGenerationError: If key generation fails
            ValidationError: If validation fails
        """
        logger.info("Adding peer to configuration")

        # Generate keys if not provided
        if keri_aid is not None:
            self.remove_peer_from_config_by_aid(config, keri_aid)
            public_key = self.key_generator.generate_peer_key(keri_aid)

        if public_key is None:
            raise ValueError("Either public_key or keri_aid must be provided")

        # Create peer
        peer = WireguardPeer(
            public_key=public_key,
            allowed_ips=allowed_ips if isinstance(allowed_ips, list) else [allowed_ips],  # type: ignore
            endpoint=endpoint,
            persistent_keepalive=persistent_keepalive,
            preshared_key=preshared_key,
            keri_aid_qb64=keri_aid,
            peer_name=peer_name,
        )

        # Add to config
        config.add_peer(peer)

        logger.info(f"Added peer {public_key[:8]}... to configuration")

        return peer

    @staticmethod
    def remove_peer_from_config(config: WireguardConfig, public_key: str) -> bool:
        """
        Remove a peer from the configuration.

        Args:
            config: Configuration to remove peer from
            public_key: Public key of peer to remove

        Returns:
            True if peer was removed, False if not found
        """
        logger.info(f"Removing peer {public_key[:8]}... from configuration")
        return config.remove_peer(public_key)

    @staticmethod
    def remove_peer_from_config_by_aid(config: WireguardConfig, aid: str) -> bool:
        """
        Remove a peer from the configuration.

        Args:
            config: Configuration to remove peer from
            aid: KERI AID of peer to remove

        Returns:
            True if peer was removed, False if not found
        """
        logger.info(f"Removing peer with aid: {aid[:8]}... from configuration")
        return config.remove_peer_by_aid(aid)

    @staticmethod
    def update_interface_port(config: WireguardConfig, listen_port: int) -> None:
        """
        Update the interface listen port.

        Args:
            config: Configuration to update
            listen_port: New listen port

        Raises:
            ValidationError: If validation fails
        """
        logger.info(f"Updating interface listen port to {listen_port}")
        InterfaceValidator.validate_listen_port(listen_port)
        config.interface.listen_port = listen_port
        config.modified_at = datetime.datetime.now(datetime.UTC)

    def load_config(self, path: Path) -> WireguardConfig:
        """
        Load a configuration from a file.

        Args:
            path: Path to configuration file

        Returns:
            Loaded WireguardConfig

        Raises:
            ConfigParseError: If parsing fails
        """
        logger.info(f"Loading configuration from {path}")
        return WireguardConfigParser.parse_file(path)

    def save_config(
        self, config: WireguardConfig, path: Path, backup: bool = True
    ) -> None:
        """
        Save a configuration to a file.

        Args:
            config: Configuration to save
            path: Path to save to
            backup: Whether to create a .bak backup if file exists

        Raises:
            ValidationError: If validation fails
            ConfigWriteError: If writing fails
        """
        logger.info(f"Saving configuration to {path}")

        # Validate configuration
        self.validate_config(config)

        # Create backup if requested and file exists
        if backup and path.exists():
            backup_path = path.with_suffix(path.suffix + ".bak")
            logger.info(f"Creating backup at {backup_path}")
            try:
                shutil.copy2(path, backup_path)
            except PermissionError:
                logger.warning(
                    f"Cannot create backup at {backup_path}: permission denied"
                )

        # Write configuration
        WireguardConfigWriter.write_file(config, path)

    def validate_config(self, config: WireguardConfig) -> bool:
        """
        Validate a configuration.

        Args:
            config: Configuration to validate

        Returns:
            True if valid

        Raises:
            ValidationError: If validation fails
        """
        logger.info("Validating configuration")
        ConfigValidator.validate_config(config)
        logger.info("Configuration is valid")
        return True

    def generate_peer_keys(self) -> Tuple[str, str]:
        """
        Generate a peer keypair.

        Returns:
            Tuple of (private_key_b64, public_key_b64)

        Raises:
            KeyGenerationError: If key generation fails
        """
        logger.info("Generating peer keypair")
        private_key, public_key, _ = self.key_generator.generate_keypair()
        return private_key, public_key
