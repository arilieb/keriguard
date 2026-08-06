# -*- encoding: utf-8 -*-
"""
keriguard.app.sentinel.services.cred_service

Business logic for credential event processing.
"""

import asyncio
from pathlib import Path

from keri import help
from keri.core.serdering import SerderACDC
from keri.kering import MissingEntryError
from sentinel.framework.watching import LocalWatcherConnector

from keriguard.core import WireguardConfigManager
from keriguard.core.systeming import (
    restart_wireguard,
    enable_wireguard,
    start_wireguard,
)
from keriguard.core.wireguarding import PeerAIDMissingError, PeerResolutionPendingError

logger = help.ogler.getLogger()


class CredService:
    """Service for managing credential-based access control."""

    def __init__(
        self,
        hby,
        rgy,
        kgb,
        config_dir,
        hab=None,
        sentinel_aid=None,
        socket_dir="/tmp",
    ):
        self.hby = hby
        self.hab = hab
        self.kgb = kgb
        self.sentinel_aid = sentinel_aid
        self.rgy = rgy
        self.config_dir = config_dir
        self.socket_dir = socket_dir

    async def process_interface_credential(self, said: str, creder: SerderACDC):
        """
        Process credential event for access control.

        Future implementation:
        - Verify credential validity
        - Check credential type and permissions
        - Add/remove peers based on credential status
        - Implement role-based access control
        """
        payload = creder.attrib
        interface = payload.get("interface")
        metadata = payload.get("interfaceMetadata")

        interface_name = metadata.get("interfaceName", "")
        interface_description = metadata.get("interfaceDescription", "")

        recipient = payload.get("i")
        if (hab := self.hby.habs.get(recipient)) is None:
            logger.info(f"Recipient {recipient} not found in hby, this is for a peer.")
            return

        config_path = Path(self.config_dir) / f"{interface_name}.conf"
        manager = WireguardConfigManager(hab=hab)
        config = None

        if config_path.exists() and config_path.is_file():
            try:
                config = manager.load_config(config_path)
                config.address = interface.get("address")
                config.listen_port = interface.get("listenPort")
                config.dns = interface.get("dns", None)
                config.mtu = interface.get("mtu")
                config.table = interface.get("table", None)
                config.config_name = interface_name
                config.description = interface_description
            except Exception as e:
                logger.warning(
                    f"Could not load existing config at {config_path}: {e}; regenerating"
                )
                config = None

        if config is None:
            config = manager.generate_config(
                address=interface.get("address"),
                listen_port=interface.get("listenPort"),
                dns=interface.get("dns", None),
                mtu=interface.get("mtu"),
                table=interface.get("table", None),
                config_name=interface_name,
                description=interface_description,
            )
            registrar = self.kgb.get_registrar()
            if registrar and registrar.endpoint:
                manager.add_peer_to_config(
                    config,
                    allowed_ips=registrar.ipaddress,
                    endpoint=registrar.endpoint,
                    persistent_keepalive=None,
                    preshared_key=None,
                    peer_name="registrar-keriguard",
                    keri_aid=registrar.keriguard_aid,
                )

        # Add pre/post up/down scripts if provided
        # Handle argument names with underscores (argparse converts dashes to underscores)
        config.interface.pre_up = interface.get("preUp")
        config.interface.post_up = interface.get("postUp")
        config.interface.pre_down = interface.get("preDown")
        config.interface.post_down = interface.get("postDown")

        # Save configuration
        manager.save_config(
            config, Path(self.config_dir) / f"{interface_name}.conf", backup=True
        )

        config_path = str(Path(self.config_dir) / f"{interface_name}.conf")
        await enable_wireguard(interface_name)
        await start_wireguard(interface_name, config_path)

        logger.debug(f"Interface credential service processing complete for {said}")

    async def process_connection_credential(self, said: str, creder: SerderACDC):
        """
        Process credential event for access control.

        Future implementation:
        - Verify credential validity
        - Check credential type and permissions
        - Add/remove peers based on credential status
        - Implement role-based access control
        """
        try:
            edges = creder.edge

            # Extract peer1 and peer2 from edges
            peer1 = edges.get("peer1")
            peer2 = edges.get("peer2")

            if not peer1 or not peer2:
                logger.error(f"Connection credential {said} missing peer1 or peer2")
                return

            # Clone both interface credentials
            peer1_interface_creder, *_ = self.rgy.reger.cloneCred(said=peer1.get("n"))
            peer2_interface_creder, *_ = self.rgy.reger.cloneCred(said=peer2.get("n"))

            if not peer1_interface_creder or not peer2_interface_creder:
                logger.error(
                    f"Failed to load interface credentials for connection {said}"
                )
                return

            # Determine which peer is local by checking interface credential recipients
            peer1_recipient = peer1_interface_creder.attrib.get("i")
            peer2_recipient = peer2_interface_creder.attrib.get("i")

            # Check if peer1's interface belongs to this host
            if (hab := self.hby.habs.get(peer1_recipient)) is not None:
                # peer1 is local, peer2 is remote
                local_interface_creder = peer1_interface_creder
                remote_interface_creder = peer2_interface_creder
                remote_peer = peer2
                logger.debug(
                    f"Matched peer1 interface to local host: {peer1_recipient}"
                )
            # Check if peer2's interface belongs to this host
            elif (hab := self.hby.habs.get(peer2_recipient)) is not None:
                # peer2 is local, peer1 is remote
                local_interface_creder = peer2_interface_creder
                remote_interface_creder = peer1_interface_creder
                remote_peer = peer1
                logger.debug(
                    f"Matched peer2 interface to local host: {peer2_recipient}"
                )
            else:
                # Neither peer is local, ignore this credential
                logger.debug(
                    f"Neither peer interface belongs to this host, ignoring credential {said}"
                )
                return

            # Extract interface name from local interface credential
            local_payload = local_interface_creder.attrib
            metadata = local_payload.get("interfaceMetadata")
            interface_name = metadata.get("interfaceName")

            config_path = Path(self.config_dir) / f"{interface_name}.conf"
            if not config_path.exists() or not config_path.is_file():
                logger.error(
                    f"Interface configuration file not found for {interface_name}"
                )
                return

            manager = WireguardConfigManager(hab=hab)
            config = manager.load_config(config_path)

            # Extract peer configuration from remote peer object
            allowed_ips = remote_peer.get("allowedIps", [])
            endpoint = remote_peer.get("endpoint")
            persistent_keepalive = remote_peer.get("persistentKeepalive")
            preshared_key = remote_peer.get("presharedKey")

            # Extract peer name from connection metadata
            connection_metadata = remote_peer.get("connectionMetadata", {})
            peer_name = connection_metadata.get("connectionName")

            # Get remote AID from remote interface credential
            remote_aid = remote_interface_creder.attrib.get("i")

            # Generate peer with auto-generated keys
            logger.info(f"Generating peer keys using KERI identity: {hab.pre}")
            try:
                manager.add_peer_to_config(
                    config,
                    allowed_ips=allowed_ips,
                    endpoint=endpoint,
                    persistent_keepalive=persistent_keepalive,
                    preshared_key=preshared_key,
                    peer_name=peer_name,
                    keri_aid=remote_aid,
                )
            except PeerAIDMissingError:
                logger.warning(
                    f"Peer AID {remote_aid} not found in kevers for credential {said}. "
                    f"Queuing background resolution and signalling caller to retry."
                )
                if self.hab and self.sentinel_aid:
                    asyncio.create_task(
                        self.resolve_peer_aid_and_retry(
                            said=said, creder=creder, missing_aid=remote_aid
                        )
                    )
                    raise PeerResolutionPendingError(
                        f"Peer AID {remote_aid} queued for resolution; retry after watcher "
                        f"fetches the KEL from witnesses"
                    )
                else:
                    raise

            # Save updated configuration
            manager.save_config(config, config_path, backup=True)

            conn_config_path = str(Path(self.config_dir) / f"{interface_name}.conf")
            await restart_wireguard(interface_name, conn_config_path)

        except MissingEntryError:
            logger.error(f"Missing entry for interface credential: {said}")
            return

        logger.info(f"Connection credential service processing complete for {said}")

    async def resolve_peer_aid_and_retry(
        self,
        said: str,
        creder: SerderACDC,
        missing_aid: str,
        max_attempts: int = 10,
        base_delay: float = 1.0,
    ):
        """
        Retry connection credential processing when peer AID is missing.

        This method attempts to resolve a missing peer AID by:
        1. Processing escrows to pull in missing key state
        2. Checking if AID appears in kevers
        3. Retrying the connection credential processing

        Args:
            said: Credential SAID
            creder: Connection credential
            missing_aid: The AID that was missing
            max_attempts: Maximum retry attempts (default: 10)
            base_delay: Base delay for exponential backoff in seconds (default: 1.0)
        """
        logger.info(
            f"Starting peer AID resolution for {missing_aid} (credential {said})"
        )
        watcher_connector = LocalWatcherConnector(
            self.hby, self.hab, self.sentinel_aid, socket_dir=self.socket_dir
        )
        watcher_connector.watch(missing_aid, None)

        for attempt in range(1, max_attempts + 1):
            # Process escrows to try to resolve missing AID
            self.hby.kvy.processEscrows()

            # Check if AID is now available
            if missing_aid in self.hby.kevers:
                logger.info(
                    f"Peer AID {missing_aid} resolved after {attempt} attempt(s)"
                )
                # Retry the connection processing
                try:
                    await self.process_connection_credential(said, creder)
                    logger.info(
                        f"Successfully processed connection credential {said} after AID resolution"
                    )
                    return
                except Exception as e:
                    logger.error(
                        f"Failed to process connection credential after AID resolution: {e}"
                    )
                    return

            logger.info(
                f"Attempt {attempt}/{max_attempts} to resolve peer AID {missing_aid} failed"
            )

            # If this wasn't the last attempt, wait before retrying
            if attempt < max_attempts:
                delay = base_delay * (2 ** (attempt - 1))
                logger.debug(f"Waiting {delay}s before next retry")
                await asyncio.sleep(delay)

        logger.error(
            f"Failed to resolve peer AID {missing_aid} after {max_attempts} attempts. "
            f"Connection credential {said} could not be processed. "
            f"User may need to run: kli oobi resolve --name <name> --oobi <oobi-url>"
        )
