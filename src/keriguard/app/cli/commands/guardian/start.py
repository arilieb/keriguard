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
from keriguard.core.initializing import KERIGuardConfig
from keriguard.db.basing import KERIGuardBaser

parser = argparse.ArgumentParser(description="Start KERIguard Sentinel event handler")
parser.set_defaults(handler=lambda args: start(args))
parser.add_argument(
    "--config",
    "-c",
    type=str,
    required=False,
    default=None,
    help="Path to YAML configuration file (optional, CLI args override config values)",
)
parser.add_argument(
    "--sentinel-aid",
    "-s",
    type=str,
    required=False,
    help="AID of the Sentinel to start",
)
parser.add_argument(
    "--sentinel-export-dir",
    "-e",
    type=str,
    required=False,
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
    "-d",
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


def merge_config(args, config_data):
    """
    Merge config file with CLI args, giving CLI precedence.

    Args:
        args: Parsed command-line arguments
        config_data: Loaded KERIGuardConfig or None

    Returns:
        dict: Merged configuration values
    """
    # Define defaults (must match argparse defaults)
    defaults = {
        "poll_interval": 2.0,
        "config_dir": "/etc/wireguard",
        "name": "keriguard",
        "alias": "keriguard-sentinel",
        "base": "",
        "loglevel": "INFO",
    }

    def get_value(cli_val, cli_default, config_getter):
        """Get merged value: CLI arg if not default, else config, else default."""
        if cli_val != cli_default:
            return cli_val
        if config_data:
            config_val = config_getter()
            if config_val is not None:
                return config_val
        return cli_default

    return {
        "sentinel_aid": args.sentinel_aid
        or (config_data.sentinel_aid if config_data else None),
        "sentinel_export_dir": args.sentinel_export_dir
        or (config_data.sentinel_export_dir if config_data else None),
        "poll_interval": get_value(
            args.poll_interval,
            defaults["poll_interval"],
            lambda: config_data.poll_interval if config_data else None,
        ),
        "config_dir": get_value(
            args.config_dir,
            defaults["config_dir"],
            lambda: config_data.config_dir if config_data else None,
        ),
        "name": get_value(
            args.name,
            defaults["name"],
            lambda: config_data.name if config_data else None,
        ),
        "alias": get_value(
            args.alias,
            defaults["alias"],
            lambda: config_data.alias if config_data else None,
        ),
        "base": get_value(
            args.base,
            defaults["base"],
            lambda: config_data.base if config_data else None,
        ),
        "bran": args.bran or (config_data.passcode if config_data else None),
        "loglevel": get_value(
            args.loglevel,
            defaults["loglevel"],
            lambda: config_data.loglevel if config_data else None,
        ),
        "logfile": args.logfile or (config_data.logfile if config_data else None),
    }


def start(args):
    # Load config file if provided
    config_data = None
    if args.config:
        try:
            config_data = KERIGuardConfig.load(args.config)
        except FileNotFoundError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Error loading config file: {e}", file=sys.stderr)
            return 1

    # Merge config file with CLI args (CLI takes precedence)
    config = merge_config(args, config_data)

    # Validate required parameters
    if not config["sentinel_aid"]:
        print(
            "Error: Sentinel AID is required (via --sentinel-aid or config file)",
            file=sys.stderr,
        )
        return 1

    if not config["sentinel_export_dir"]:
        print(
            "Error: Sentinel export directory is required (via --sentinel-export-dir or config file)",
            file=sys.stderr,
        )
        return 1

    help.ogler.level = logging.getLevelName(config["loglevel"])
    base_formatter = logging.Formatter(FORMAT)  # basic format
    base_formatter.default_msec_format = None
    help.ogler.baseConsoleHandler.setFormatter(base_formatter)

    if config["logfile"] is not None:
        help.ogler.headDirPath = config["logfile"]
        help.ogler.reopen(name="keriguard", temp=False, clear=True)

    logger = help.ogler.getLogger()

    export_dir = Path(config["sentinel_export_dir"])
    if not export_dir.exists():
        logger.error(f"Export directory does not exist: {export_dir}")
        print(f"Error: Export directory not found: {export_dir}", file=sys.stderr)
        return 1

    hby = habbing.Habery(name=config["name"], base=config["base"], bran=config["bran"])
    hab = hby.habByName(config["alias"])
    rgy = credentialing.Regery(hby=hby, name=hby.name, base=hby.base, temp=hby.temp)
    kgb = KERIGuardBaser(name=hby.name, base=hby.base, temp=hby.temp)

    # Create sentinel handler configuration
    sentinel_config = SentinelHandlerConfig(
        export_dir=str(export_dir),
        sentinel_aid=config["sentinel_aid"],
        poll_interval=config["poll_interval"],
        config_dir=config["config_dir"],
        hby=hby,
        hab=hab,
        rgy=rgy,
        kgb=kgb,
    )

    # Create and register handler
    handler = KeriguardEventHandler(sentinel_config)
    register_handler(handler)

    logger.info("Starting Keriguard Sentinel handler")
    logger.info(f"  Export directory: {export_dir}")
    logger.info(f"  Config directory: {sentinel_config.config_dir}")
    logger.info(f"  Poll interval: {sentinel_config.poll_interval}s")
    logger.info(f"  KERI name: {hby.name}")
    logger.info(f"  KERI alias: {hab.name}")

    # Run the Sentinel framework
    # This blocks until SIGINT/SIGTERM
    run(
        export_dir=str(export_dir),
        poll_interval=sentinel_config.poll_interval,
        hby=hby,
        rgy=rgy,
    )

    logger.info("Keriguard Sentinel handler stopped")
    return 0
