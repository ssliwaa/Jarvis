#!/usr/bin/env python3
"""Manage Jarvis operator credentials. Values are read from a prompt, never argv."""
from __future__ import annotations

import argparse
import getpass
import sys

from operator_tools import SecretStore, ToolError


def main() -> int:
    parser = argparse.ArgumentParser(description="Jarvis operator credential store")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="show credential names and types")
    for name in ("set", "set-totp", "remove"):
        command = sub.add_parser(name)
        command.add_argument("name")
    args = parser.parse_args()
    store = SecretStore()
    try:
        if args.command == "list":
            for item in store.names():
                print(f"{item['name']}\t{item['type']}")
            return 0
        if args.command == "remove":
            store.remove(args.name)
            print(f"Removed {args.name}.")
            return 0
        if args.command == "set":
            value = getpass.getpass("Credential value (hidden): ")
            if not value:
                print("No value entered; nothing saved.", file=sys.stderr)
                return 1
            store.put(args.name, {"type": "password", "value": value})
            print(f"Stored {args.name} as a password. The value is not printed.")
            return 0
        if args.command == "set-totp":
            value = getpass.getpass("Base32 TOTP seed (hidden): ")
            if not value:
                print("No seed entered; nothing saved.", file=sys.stderr)
                return 1
            store.put(args.name, {"type": "totp", "totp": value})
            print(f"Stored {args.name} as a TOTP seed. The seed is not printed.")
            return 0
    except ToolError as error:
        print(str(error), file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
