#!/usr/bin/env python3

import logging
import json
import pathlib
import sys
import geocoder
import tomlkit
import argparse
import pycountry
from aiohttp import web

valid_keyboard_layouts = [
    "de",
    "de-ch",
    "dk",
    "en-gb",
    "en-us",
    "es",
    "fi",
    "fr",
    "fr-be",
    "fr-ca",
    "fr-ch",
    "hu",
    "is",
    "it",
    "jp",
    "lt",
    "mk",
    "nl",
    "no",
    "pl",
    "pt",
    "pt-br",
    "se",
    "si",
    "tr",
]


def get_keyboard(args):
    selected_keyboard_layout = args.keyboard
    while selected_keyboard_layout not in valid_keyboard_layouts:
        if selected_keyboard_layout is not None:
            print(f"{selected_keyboard_layout} is not a valid keyboard layout")
        print("Select keyboard layout (enter number or letters):")
        for i, item in enumerate(valid_keyboard_layouts, start=1):
            print(f"{i}. {item}")

        selected_keyboard_layout = input()
        if selected_keyboard_layout.isdigit():
            index = int(selected_keyboard_layout) - 1
            if 0 <= index < len(valid_keyboard_layouts):
                selected_keyboard_layout = valid_keyboard_layouts[index]
    print(f"Selected keyboard layout: {selected_keyboard_layout}")
    return selected_keyboard_layout


def get_countrycode(args):
    selected_countrycode = str(args.countrycode or "")
    while pycountry.countries.get(alpha_2=selected_countrycode) is None:
        if selected_countrycode is not "":
            print(f"{selected_countrycode} is not a valid countrycode")
        print(
            "Select ISO 3166-1 alpha 2 countrycode to use (for example DE, FR, GB, or SE). See https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2 for full list:"
        )
        # Get location based on IP
        g = geocoder.ip("me")

        # Extract the country code
        do_suggest = False
        if pycountry.countries.get(alpha_2=str(g.country or "")) is not None:
            print(
                f"(Suggested countrycode is {g.country}, press Enter to accept, or explictly type a countrycode)"
            )
            do_suggest = True

        selected_countrycode = input()
        if selected_countrycode is "" and do_suggest:
            selected_countrycode = g.country

    print(f"Selected countrycode: {selected_countrycode}")
    return selected_countrycode


def command_begin(args):
    selected_keyboard_layout = get_keyboard(args)
    selected_countrycode = get_countrycode(args)


def command_addhost(args):
    print("Addhost")


def command_unknown(args, parser):
    parser.print_usage()
    s = parser.format_usage()
    subcommands = s[s.find("{") + 1 : s.find("}")].split(",")
    subcommands_quote_string = ",".join(f"'{x}'" for x in subcommands)
    sys.exit(
        f"indie: error: argument {{{','.join(subcommands)}}}: invalid choice: '' (choose from {subcommands_quote_string})"
    )


def validate_countrycode(value):
    if pycountry.countries.get(alpha_2=value) is None:
        raise argparse.ArgumentTypeError(
            f"{value} is not a valid ISO 3166-1 alpha 2 countrycode"
        )
    return value


def main():
    parser = argparse.ArgumentParser()
    parser.set_defaults(func=(lambda args, p=parser: command_unknown(args, p)))
    subparsers = parser.add_subparsers(help="Available subcommands")

    # begin
    p_begin = subparsers.add_parser(
        "begin", help="Begin the initial setup of the infrastructure"
    )
    p_begin.add_argument(
        "--keyboard", choices=valid_keyboard_layouts, help="Keyboard layout to use."
    )
    p_begin.add_argument(
        "--countrycode",
        type=validate_countrycode,
        help="ISO 3166-1 alpha 2 countrycode to use (for example DE, FR, GB, or SE). See https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2 for full list.",
    )
    p_begin.set_defaults(func=command_begin)

    # addhost
    p_addhost = subparsers.add_parser(
        "addhost", help="Add a new physical host machine to the infrastructure"
    )
    p_addhost.add_argument("-n", "--hostname", required=True)
    p_addhost.set_defaults(func=command_addhost)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
