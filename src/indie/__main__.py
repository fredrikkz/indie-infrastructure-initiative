#!/usr/bin/env python3

import os
import logging
import json
import pathlib
import sys
import geocoder
import tomlkit
import argparse
import pycountry
import validators
import tzlocal
from zoneinfo import available_timezones
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

indie_toml_file = ".indie/indie.toml"
indie_toml = tomlkit.document()


def write_toml(table: str, data: dict):
    indie_toml[table] = data

    os.makedirs(os.path.dirname(indie_toml_file), exist_ok=True)
    with open(indie_toml_file, "w", encoding="utf-8") as file:
        file.write(indie_toml.as_string())


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
        if selected_countrycode != "":
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
                f"(Suggested countrycode is {g.country}, press Enter to accept, or explictly enter a countrycode)"
            )
            do_suggest = True

        selected_countrycode = str(input() or "")
        if selected_countrycode == "" and do_suggest:
            selected_countrycode = g.country

    print(f"Selected countrycode: {selected_countrycode}")
    return selected_countrycode


def get_domain(args):
    selected_domain = args.domain
    while not validators.domain(selected_domain):
        if selected_domain is not None:
            print(f"{selected_domain} is not a valid domain")
        print("Select domain:")

        selected_domain = input()
    print(f"Selected domain: {selected_domain}")
    return selected_domain


def get_email(args):
    selected_email = args.email
    while not validators.email(selected_email):
        if selected_email is not None:
            print(f"{selected_email} is not a valid email")
        print("Select email:")

        selected_email = input()
    print(f"Selected email: {selected_email}")
    return selected_email


def get_timezone(args):
    selected_timezone = args.timezone

    while selected_timezone not in available_timezones():
        if selected_timezone is not None:
            print(f"{selected_timezone} is not a valid timezone")
        print("Select timezone:")

        suggested_timezone = str(tzlocal.get_localzone())

        do_suggest = False
        if suggested_timezone is not None:
            print(
                f"(Suggested timezone is {suggested_timezone}, press Enter to accept, or explictly enter a timezone)"
            )
            do_suggest = True

        selected_timezone = str(input() or "")
        if selected_timezone == "" and do_suggest:
            selected_timezone = suggested_timezone
    print(f"Selected timezone: {selected_timezone}")
    return selected_timezone


def command_begin(args):
    selected_keyboard_layout = get_keyboard(args)
    selected_countrycode = get_countrycode(args)
    selected_domain = get_domain(args)
    selected_email = get_email(args)
    selected_timezone = get_timezone(args)
    write_toml(
        "indie",
        {
            "global": {
                "keyboard": selected_keyboard_layout,
                "countrycode": selected_countrycode,
                "domain": selected_domain,
                "email": selected_email,
                "timezone": selected_timezone,
            }
        },
    )


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


def get_toml_default(key):
    try:
        return indie_toml["indie"]["global"][key]
    except KeyError:
        return None


def main():
    # Read default values, if possible
    try:
        with open(indie_toml_file, "r", encoding="utf-8") as file:
            global indie_toml
            indie_toml = tomlkit.load(file)
    except FileNotFoundError:
        pass

    parser = argparse.ArgumentParser()
    parser.set_defaults(func=(lambda args, p=parser: command_unknown(args, p)))
    subparsers = parser.add_subparsers(help="Available subcommands")

    # begin
    p_begin = subparsers.add_parser(
        "begin", help="Begin the initial setup of the infrastructure"
    )
    p_begin.add_argument(
        "--keyboard",
        choices=valid_keyboard_layouts,
        help="Keyboard layout to use.",
        default=get_toml_default("keyboard"),
    )
    p_begin.add_argument(
        "--countrycode",
        type=validate_countrycode,
        help="ISO 3166-1 alpha 2 countrycode to use (for example DE, FR, GB, or SE). See https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2 for full list.",
        default=get_toml_default("countrycode"),
    )
    p_begin.add_argument("--domain", default=get_toml_default("domain"))
    p_begin.add_argument("--email", default=get_toml_default("email"))
    p_begin.add_argument("--timezone", default=get_toml_default("timezone"))
    p_begin.set_defaults(func=command_begin)

    # addhost
    p_addhost = subparsers.add_parser(
        "addhost", help="Add a new physical host machine to the infrastructure"
    )
    p_addhost.set_defaults(func=command_addhost)

    args = parser.parse_args()

    args.func(args)


if __name__ == "__main__":
    main()
