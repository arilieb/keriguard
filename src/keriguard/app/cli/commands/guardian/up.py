# -*- encoding: utf-8 -*-
"""
KERI
kerugard.app.cli.commands module

Initialize the KERIGuard server
"""

import argparse
import asyncio
import logging
import random

from keri import help, kering
from keri.app import habbing, connecting
from keri.app.keeping import Algos
from keri.core import parsing
from keri.kering import ConfigurationError
from sentinel.core.initializing import SentinelConfig
from sentinel.framework.connecting import connect_to_healthkeri

from keriguard.core.initializing import (
    load_schema,
    load_oobi,
    KeriguardConfig,
)
from keriguard.core.systeming import (
    enable_guardian,
    enable_sentinel,
    start_sentinel,
    start_guardian,
)
from keriguard.core.wireguarding import SCHEMA_OOBIS, Schema
from keriguard.db.basing import KERIGuardBaser

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description="Initialize a new KERIGuard instance.")
parser.set_defaults(handler=lambda args: asyncio.run(up(args)))
parser.add_argument(
    "--config",
    "-c",
    help="Path to the configuration file",
    required=True,
    default=None,
)
parser.add_argument(
    "--name",
    "-n",
    help="Name of the database environment",
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
    "--alias",
    "-a",
    help="human readable alias for the new identifier prefix",
    required=False,
    default="keriguard",
)
parser.add_argument(
    "--passcode",
    "-p",
    help="21 character encryption passcode for keystore (is not saved)",
    dest="bran",
    default=None,
)  # passcode => bran
parser.add_argument(
    "--salt",
    "-s",
    help="qualified base64 salt for creating key pairs",
    required=False,
    default=None,
)
parser.add_argument(
    "--loglevel",
    default="ERROR",
    help="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
)
parser.add_argument(
    "--logfile",
    action="store",
    required=False,
    default=None,
    help="path of the log file. If not defined, logs will not be written to the file.",
)
parser.add_argument(
    "--sentinel-config-path",
    default=None,
    required=False,
    help="Path to sentinel config file",
)

FORMAT = "%(asctime)s [keriguard] %(levelname)-8s %(message)s"


async def up(args):
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    help.ogler.level = logging.getLevelName(args.loglevel)
    base_formatter = logging.Formatter(FORMAT)  # basic format
    base_formatter.default_msec_format = None
    help.ogler.baseConsoleHandler.setFormatter(base_formatter)

    if args.logfile is not None:
        help.ogler.headDirPath = args.logfile
        help.ogler.reopen(name="keriguard", temp=False, clear=True)

    config = KeriguardConfig.load(args.config)
    keriguard_name = args.name
    keriguard_alias = args.alias

    sentinel_name = f"{keriguard_name}-sentinel"
    sentinel_alias = f"{keriguard_alias}-sentinel"

    kwa = dict()
    kwa["salt"] = args.salt
    kwa["bran"] = args.bran
    if args.salt is None:
        kwa["algo"] = Algos.randy

    # Create environment and identifier for the ACDC Auth Server
    keriguard_hby = habbing.Habery(
        name=keriguard_name, base=args.base, temp=False, **kwa
    )
    if not (keriguard_hab := keriguard_hby.habByName(keriguard_alias)):
        keriguard_hab = keriguard_hby.makeHab(
            name=keriguard_alias,
            transferable=True,
            icount=1,
            isith="1",
            ncount=1,
            nsith="1",
            toad=0,
        )

    # Create the environment and identifier for the sentinel
    sentinel_hby = habbing.Habery(name=sentinel_name, base=args.base, temp=False, **kwa)
    if not (sentinel_hab := sentinel_hby.habByName(sentinel_alias)):
        sentinel_hab = sentinel_hby.makeHab(
            name=sentinel_alias,
            transferable=not config.local,
            icount=1,
            isith="1",
            ncount=1,
            nsith="1",
            toad=0,
        )

    # Load KERIGuard schema in both databases
    for hby in (sentinel_hby, keriguard_hby):
        load_schema(
            hby=hby,
            schema_oobi=SCHEMA_OOBIS[Schema.INTERFACE_SCHEMA],
            schema_said=Schema.INTERFACE_SCHEMA,
        )
        load_schema(
            hby=hby,
            schema_oobi=SCHEMA_OOBIS[Schema.CONNECTION_SCHEMA],
            schema_said=Schema.CONNECTION_SCHEMA,
        )

    keriguard_org = connecting.Organizer(hby=keriguard_hby)

    icp = sentinel_hab.makeOwnEvent(sn=0)
    parsing.Parser().parse(ims=bytearray(icp), kvy=keriguard_hab.kvy)

    keriguard_org.update(pre=sentinel_hab.pre, data=dict(alias=sentinel_alias))

    load_oobi(hby=keriguard_hby, oobi=config.issuer.oobi, alias="issuer")
    load_oobi(hby=sentinel_hby, oobi=config.issuer.oobi, alias="issuer")

    if config.local:
        # Local mode: witnesses have keriguard's events; use OOBI to load into sentinel keystore.
        load_oobi(hby=keriguard_hby, oobi=config.registrar.oobi, alias="registrar")
        load_oobi(
            hby=keriguard_hby,
            oobi=config.registrar.keriguard.oobi,
            alias="registrar-keriguard",
        )
        load_oobi(hby=sentinel_hby, oobi=config.registrar.oobi, alias="registrar")
        load_oobi(
            hby=sentinel_hby,
            oobi=config.registrar.keriguard.oobi,
            alias="registrar-keriguard",
        )

        if (
            config.registrar.aid not in keriguard_hby.kevers
            or config.registrar.keriguard.aid not in keriguard_hby.kevers
            or config.issuer.aid not in keriguard_hby.kevers
        ):
            raise ConfigurationError(
                "Unable to resolve configuration root identifiers. Please check your configuration"
            )
    else:
        if config.issuer.aid not in keriguard_hby.kevers:
            raise ConfigurationError(
                "Unable to resolve issuer identifier. Please check your configuration"
            )

    sentinel_config = SentinelConfig()
    sentinel_config.name = sentinel_name
    sentinel_config.alias = sentinel_alias
    sentinel_config.server_name = keriguard_name
    sentinel_config.server_alias = keriguard_alias
    sentinel_config.bran = args.bran
    sentinel_config.base = args.base
    sentinel_config.uxd = True
    sentinel_config.local = config.local
    sentinel_config.export_dir = f"/usr/local/var/sentinel/{args.name}"

    sentinel_config.issuer.aid = config.issuer.aid
    sentinel_config.issuer.oobi = config.issuer.oobi

    if config.local:
        sentinel_config.registrar.aid = config.registrar.aid
        sentinel_config.registrar.oobi = config.registrar.oobi
        sentinel_config.registrar.url = config.registrar.url

    else:
        # Use Sentinel method with auth_key to register the server
        await connect_to_healthkeri(
            server_name=keriguard_name,
            sentinel_hby=sentinel_hby,
            sentinel_hab=sentinel_hab,
            auth_key=config.server.auth_key,  # type: ignore
            server_hby=keriguard_hby,
            server_hab=keriguard_hab,
            witness=True,
        )

    # Use OS specific service enable and start for Guardian and Sentinel
    await enable_sentinel()
    await enable_guardian()

    await start_sentinel()
    await start_guardian()

    if not keriguard_hab.kever.wits:
        raise ConfigurationError(f"KERIguard alias {keriguard_alias} has no witnesses")

    print(f"\n\nKERIGuard AID: {keriguard_hab.pre}\n")

    witness_aid = random.choice(keriguard_hab.kever.wits)
    urls = keriguard_hab.fetchUrls(
        eid=witness_aid, scheme=kering.Schemes.http
    ) or keriguard_hab.fetchUrls(eid=witness_aid, scheme=kering.Schemes.https)

    if not urls:
        raise kering.ConfigurationError(
            f"unable to query witness {witness_aid}, no http endpoint"
        )

    url = (
        urls[kering.Schemes.https]
        if kering.Schemes.https in urls
        else urls[kering.Schemes.http]
    )
    keriguard_oobi = f"{url.rstrip("/")}/oobi/{keriguard_hab.pre}/witness"
    print("\n\nKERIGuard OOBI:")
    print(keriguard_oobi)
    print()

    load_oobi(hby=sentinel_hby, oobi=keriguard_oobi, alias="keriguard")
    connecting.Organizer(hby=sentinel_hby).update(
        pre=keriguard_hab.pre,
        data=dict(alias=keriguard_alias, oobi=keriguard_oobi),
    )

    if args.sentinel_config_path:
        sentinel_config.save(args.sentinel_config_path)
    else:
        sentinel_config.save(f"/etc/sentinel/{args.name}.yaml")

    kgb = KERIGuardBaser(name=args.name, base=args.base)

    if config.local:
        kgb.set_registrar(
            aid=config.registrar.aid,
            keriguard_aid=config.registrar.keriguard.aid,
            oobi=config.registrar.oobi,
            keriguard_oobi=config.registrar.keriguard.oobi,
            url=config.registrar.url,
            ipaddress=config.registrar.keriguard.ipaddress,
            endpoint=config.registrar.keriguard.endpoint,
        )

    kgb.set_issuer(aid=config.issuer.aid, oobi=config.issuer.oobi)
