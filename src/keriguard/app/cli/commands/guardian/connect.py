# -*- encoding: utf-8 -*-
"""
keriguard.app.cli module

"""

import argparse
import asyncio
import sys

from keri import help, kering
from keri.app import connecting
from keri.app.cli.common import existing
from keri.core import serdering, parsing, coring
from keri.peer import exchanging
from keri.vdr import credentialing, verifying
from sentinel.framework.watching import LocalWatcherConnector

from keriguard.app.sentinel.services import CredService
from keriguard.core.wireguarding import Schema
from keriguard.db.basing import KERIGuardBaser

parser = argparse.ArgumentParser(
    description="Process interface credential and generate Wireguard configuration"
)
parser.set_defaults(handler=lambda args: asyncio.run(process(args)))
parser.add_argument(
    "--name",
    "-n",
    help="keystore name and file location of KERI keystore",
    required=False,
    default="keriguard",
)
parser.add_argument(
    "--alias",
    "-a",
    help="human readable alias for the new identifier prefix",
    required=False,
    default="keriguard",
)
parser.add_argument(
    "--base",
    "-b",
    help="additional optional prefix to file location of KERI keystore",
    required=False,
    default="",
)
parser.add_argument(
    "--passcode",
    "-p",
    help="21 character encryption passcode for keystore (is not saved)",
    dest="bran",
    default=None,
)  # passcode => bran

# Required arguments for Wireguard configuration
parser.add_argument(
    "--file",
    "-f",
    required=False,
    default=None,
    help="Credential file to load",
)

# Required arguments for Wireguard configuration
parser.add_argument(
    "--export-dir",
    required=False,
    default=".",
    help="Directory to export Wireguard configuration files",
)


logger = help.ogler.getLogger()


async def process(args):
    """Generate a Wireguard interface configuration with KERI-tracked keys."""
    name = args.name
    alias = args.alias
    bran = args.bran

    if not name:
        print("Interface name is required.")
        sys.exit(1)

    with existing.existingHab(name=name, alias=alias, base=args.base, bran=bran) as (
        hby,
        hab,
    ):
        kgb = KERIGuardBaser(name=name, base=args.base)

        sentinel_name = f"{name}-sentinel"
        org = connecting.Organizer(hby=hby)
        results = org.find("alias", sentinel_name)
        if not results:
            raise kering.ConfigurationError(
                f"Sentinel '{sentinel_name}' not found. You must run `kg up` first."
            )
        sentinel_aid = results[0].get("id")

        watcher_connector = LocalWatcherConnector(hby, hab, sentinel_aid)

        registrar = kgb.get_registrar()
        if registrar and registrar.aid in hby.kevers:
            watcher_connector.watch(registrar.aid, registrar.oobi)

        issuer = kgb.get_issuer()
        if issuer.aid in hby.kevers:
            watcher_connector.watch(issuer.aid, issuer.oobi)

        watcher_connector.watch(hab.pre, None)

        if args.file:
            data = None
            with open(args.file, "br") as file:
                data = file.read()

            if not data:
                print("KERIGuard credential file is empty or does not exist.")
                return 1

            grant = serdering.SerderKERI(raw=bytes(data))

            rgy = credentialing.Regery(
                hby=hby, name=hby.name, base=hby.base, temp=hby.temp
            )
            exc = exchanging.Exchanger(hby=hby, handlers=[])
            verifier = verifying.Verifier(hby=hby, reger=rgy.reger)
            psr = parsing.Parser(kvy=hby.kvy, tvy=rgy.tvy, vry=verifier, exc=exc)

            psr.parse(data)
            psr.kvy.processEscrows()
            rgy.tvy.processEscrows()
            verifier.processEscrows()

            pserder, pathed = exchanging.cloneMessage(hby, said=grant.said)
            embeds = grant.ked["e"]
            acdc = embeds["acdc"]

            for label in ("anc", "reg", "iss", "acdc"):
                ked = embeds[label]
                sadder = coring.Sadder(ked=ked)
                ims = bytearray(sadder.raw) + pathed[label]
                psr.parseOne(ims=ims)

            creder = serdering.SerderACDC(sad=acdc)
            if rgy.reger.saved.get(keys=(creder.said,)):

                service = CredService(hby, rgy, kgb, args.export_dir)
                match creder.schema:
                    case Schema.INTERFACE_SCHEMA:
                        await service.process_interface_credential(creder.said, creder)

                    case _:
                        print(f"Invalid credential schema: {creder.schema}")
                        return -1

            return 0

        print("Credential did not parse correctly")
        return 1
