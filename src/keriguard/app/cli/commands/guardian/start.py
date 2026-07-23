# -*- encoding: utf-8 -*-
"""
keriguard.app.cli module

"""

import argparse
import logging
import sys
from pathlib import Path

from keri import help
from keri.app import habbing
from keri.vdr import credentialing
from sentinel.framework import register_handler, run

from keriguard.app.sentinel import KeriguardEventHandler
from keriguard.app.sentinel.config import SentinelHandlerConfig
from keriguard.db.basing import KERIGuardBaser

parser = argparse.ArgumentParser(description="Start KERIguard Sentinel event handler")
parser.set_defaults(handler=lambda args: start(args))
parser.add_argument(
    "--sentinel-aid",
    "-s",
    type=str,
    required=True,
    help="AID of the Sentinel to start",
)
parser.add_argument(
    "--sentinel-export-dir",
    "-e",
    type=str,
    required=True,
    help="Directory to monitor for KERI events (contains kel/, tel/, cred/ subdirs)",
)
parser.add_argument(
    "--poll-interval",
    "-p",
    type=float,
    default=2.0,
    help="Polling interval in seconds (default: 2.0)",
)
parser.add_argument(
    "--config-dir",
    "-c",
    type=str,
    default="/etc/wireguard",
    help="Directory for Wireguard config files (default: /etc/wireguard)",
)
parser.add_argument(
    "--name",
    "-n",
    type=str,
    default="keriguard",
    help="KERI keystore name (default: keriguard)",
)
parser.add_argument(
    "--alias",
    "-a",
    type=str,
    default="keriguard-sentinel",
    help="KERI identifier alias (default: owl)",
)
parser.add_argument(
    "--base", "-b", type=str, default="", help="KERI keystore base directory"
)
parser.add_argument(
    "--passcode",
    type=str,
    dest="bran",
    default=None,
    help="21-character encryption passcode for KERI keystore",
)
parser.add_argument(
    "--loglevel",
    action="store",
    required=False,
    default="INFO",
    help="Set log level to DEBUG | INFO | WARNING | ERROR | CRITICAL. Default is INFO",
)
parser.add_argument(
    "--logfile",
    action="store",
    required=False,
    default=None,
    help="path of the log file. If not defined, logs will not be written to the file.",
)

FORMAT = "%(asctime)s [keriguard] %(levelname)-8s %(message)s"


def start(args):
    help.ogler.level = logging.getLevelName(args.loglevel)
    base_formatter = logging.Formatter(FORMAT)  # basic format
    base_formatter.default_msec_format = None
    help.ogler.baseConsoleHandler.setFormatter(base_formatter)

    if args.logfile is not None:
        help.ogler.headDirPath = args.logfile
        help.ogler.reopen(name="keriguard", temp=False, clear=True)

    logger = help.ogler.getLogger()

    export_dir = Path(args.sentinel_export_dir)
    if not export_dir.exists():
        logger.error(f"Export directory does not exist: {export_dir}")
        print(f"Error: Export directory not found: {export_dir}", file=sys.stderr)
        return 1

    hby = habbing.Habery(name=args.name, base=args.base, bran=args.bran)
    hab = hby.habByName(args.alias)
    rgy = credentialing.Regery(hby=hby, name=hby.name, base=hby.base, temp=hby.temp)
    kgb = KERIGuardBaser(name=hby.name, base=hby.base, temp=hby.temp)

    # Create configuration
    config = SentinelHandlerConfig(
        export_dir=str(export_dir),
        sentinel_aid=args.sentinel_aid,
        poll_interval=args.poll_interval,
        config_dir=args.config_dir,
        hby=hby,
        hab=hab,
        rgy=rgy,
        kgb=kgb,
    )

    # Create and register handler
    handler = KeriguardEventHandler(config)
    register_handler(handler)

    logger.info("Starting Keriguard Sentinel handler")
    logger.info(f"  Export directory: {export_dir}")
    logger.info(f"  Config directory: {config.config_dir}")
    logger.info(f"  Poll interval: {config.poll_interval}s")
    logger.info(f"  KERI name: {hby.name}")
    logger.info(f"  KERI alias: {hab.name}")

    # Run the Sentinel framework
    # This blocks until SIGINT/SIGTERM
    run(
        export_dir=str(export_dir),
        poll_interval=config.poll_interval,
        hby=hby,
        rgy=rgy,
    )

    logger.info("Keriguard Sentinel handler stopped")
    return 0
