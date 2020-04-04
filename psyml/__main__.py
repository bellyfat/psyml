#!/usr/bin/env python3
"""Cli interface for psyml."""
import argparse

from .models import PSyml


def parse_args():
    """Parse commandline arguments."""
    parser = argparse.ArgumentParser(prog="psyml")
    subparsers = parser.add_subparsers(
        help="allowed subcommands", dest="command"
    )

    # Adding commands
    encrypt = subparsers.add_parser(
        "encrypt", help="encrypt a yml file with default kms key"
    )
    save = subparsers.add_parser(
        "save", help="save parameters into parameter store"
    )
    nuke = subparsers.add_parser(
        "nuke", help="remove all the parameter store entries"
    )
    decrypt = subparsers.add_parser("decrypt", help="decrypt a yml file")
    diff = subparsers.add_parser(
        "diff", help="compare with items in parameter store"
    )
    refresh = subparsers.add_parser(
        "refresh", help="compare with items in parameter store"
    )
    for command in [encrypt, save, nuke, decrypt, diff, refresh]:
        command.add_argument("file", type=argparse.FileType(encoding="UTF-8"))
    return parser.parse_args()


def main():
    """Entrypoint for psyml cli."""
    args = parse_args()
    psyml = PSyml(args.file)
    getattr(psyml, args.command)()


if __name__ == "__main__":
    main()
