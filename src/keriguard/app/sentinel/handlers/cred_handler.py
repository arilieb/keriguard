# -*- encoding: utf-8 -*-
"""
keriguard.app.sentinel.handlers.cred_handler

Credential event handler.
"""

import asyncio

from keri.core import parsing, serdering
from keri.vdr import verifying
from sentinel.framework import CredentialEvent
from keri import help

from keriguard.core.wireguarding import Schema
from ..config import SentinelHandlerConfig
from ..services.cred_service import CredService

logger = help.ogler.getLogger()


class CredHandler:
    """Handler for credential events - manages credential-based access control."""

    def __init__(self, config: SentinelHandlerConfig):
        self.config = config
        self.rgy = config.rgy
        self.verifier = verifying.Verifier(hby=config.hby, reger=config.rgy.reger)
        self.psr = parsing.Parser(
            kvy=config.hby.kvy, tvy=self.rgy.tvy, vry=self.verifier
        )

        self.service = CredService(
            config.hby,
            config.rgy,
            config.kgb,
            config.config_dir,
            config.hab,
            config.sentinel_aid,
            config.socket_dir,
        )

    async def process(self, event: CredentialEvent):
        """
        Process credential event for access control.

        Credential events track:
        - Credential issuance (grant access)
        - Credential revocation (remove access)
        - Credential updates (change permissions)
        """
        creder = serdering.SerderACDC(raw=bytes(event.data))
        if creder.said != event.aid:
            logger.error(
                f"Credential event AID mismatch: Expected {event.aid}, got {creder.said}"
            )
            return

        logger.info(f"Processing credential event for AID: {creder.said}")
        logger.debug(f"Processing credential event with schema: {creder.schema}")

        asyncio.create_task(self.finalize_credential_load(creder))

    async def finalize_credential_load(self, creder, max_attempts=10, base_delay=1.0):

        for attempt in range(1, max_attempts + 1):

            if self.rgy.reger.saved.get(keys=(creder.said,)):

                match creder.schema:
                    case Schema.INTERFACE_SCHEMA:
                        await self.service.process_interface_credential(
                            creder.said, creder
                        )
                    case Schema.CONNECTION_SCHEMA:
                        await self.service.process_connection_credential(
                            creder.said, creder
                        )
                    case _:
                        logger.warning(f"Unknown credential schema: {creder.schema}")

                return

            self.psr.kvy.processEscrows()
            self.rgy.tvy.processEscrows()
            self.verifier.processEscrows()

            logger.info(
                f"Attempt {attempt} to finalize credential load for AID: {creder.said} failed..."
            )

            # If this wasn't the last attempt, wait before retrying
            if attempt < max_attempts:
                delay = base_delay * (2 ** (attempt - 1))
                logger.debug(f"finalize_load_credential: Waiting {delay}s before retry")
                await asyncio.sleep(delay)
