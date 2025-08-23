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
import getpass
from zoneinfo import available_timezones
from aiohttp import web
from passlib.hash import sha512_crypt
from . import __version__

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


def write_toml(data: dict):
    indie_toml.update(data)

    os.makedirs(os.path.dirname(indie_toml_file), exist_ok=True)
    with open(indie_toml_file, "w", encoding="utf-8") as file:
        file.write(indie_toml.as_string())


def get_toml_default(key):
    try:
        return indie_toml["global"][key]
    except KeyError:
        return None


def has_toml_table(*args):
    local = indie_toml
    for arg in args:
        try:
            local = local[arg]
        except KeyError:
            return False
    return True


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
        print("Select domain (for example, 'example.com'):")

        selected_domain = input()
    print(f"Selected domain: {selected_domain}")
    return selected_domain


def get_mailto(args):
    selected_mailto = args.mailto
    while not validators.email(selected_mailto):
        if selected_mailto is not None:
            print(f"{selected_mailto} is not a valid email")
        print("Select email:")

        selected_mailto = input()
    print(f"Selected email: {selected_mailto}")
    return selected_mailto


def get_timezone(args):
    selected_timezone = args.timezone

    while selected_timezone not in available_timezones():
        if selected_timezone is not None:
            print(f"{selected_timezone} is not a valid timezone")
        print(
            "Select timezone (in IANA time zone database 'Area/Location' format, for example 'Europe/Stockholm'):"
        )

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


def validate_password_hash(password):
    if password is None:
        return False
    subparts = password.split("$")
    if 4 <= len(subparts) <= 5:
        if subparts[1] != "6":  # 6 == sha512
            return False
        if len(subparts) == 5 and not subparts[2].startswith("rounds="):
            return False
        return True
    return False


def get_password(args):
    selected_password = args.root_password_hashed

    while not validate_password_hash(selected_password):
        if selected_password is not None:
            print(f"{selected_password} is not a valid password hash")
        print("Enter desired 'root' user password:")
        selected_password = sha512_crypt.hash(getpass.getpass())
        print("Repeat desired 'root' user password:")
        if not sha512_crypt.verify(getpass.getpass(), selected_password):
            print("Entered passwords didn't match, try again")
            selected_password = None
    print(f"Selected password hash: {selected_password}")
    return selected_password


def command_begin(args):
    begin_dict = {
        "domain": get_domain(args),
        "mailto": get_mailto(args),
        "keyboard": get_keyboard(args),
        "countrycode": get_countrycode(args),
        "timezone": get_timezone(args),
        "root-password-hashed": get_password(args),
    }
    write_toml(
        {"global": begin_dict},
    )


def get_hostname(args, domain):
    selected_hostname = args.hostname
    while not validators.domain(
        (selected_hostname or "") + "." + domain
    ) or has_toml_table("host", selected_hostname):
        if selected_hostname is not None:
            if not validators.domain((selected_hostname or "") + "." + domain):
                print(f"{selected_hostname + '.' + domain} is not a valid domain")
            elif has_toml_table("host", selected_hostname):
                print(f"'{selected_hostname}' already in use")
        print("Select hostname:")

        selected_hostname = input()
    print(
        f"Selected hostname: {selected_hostname}, FQDN becomes '{selected_hostname + '.' + domain}'"
    )
    return selected_hostname


# TODO: Also validate that the MAC address isn't used by any other hosts
def get_macaddress(args):
    selected_macaddress = args.macaddress
    while not validators.mac_address(selected_macaddress):
        if selected_macaddress is not None:
            print(f"{selected_macaddress} is not a valid MAC address")
        print("Select MAC address:")

        selected_macaddress = input()
    print(f"Selected MAC address: {selected_macaddress}")
    return selected_macaddress


def get_dhcp(args):
    selected_use_dhcp = args.use_dhcp
    while not isinstance(selected_use_dhcp, bool):
        string = (
            input("Do you want to use DHCP for this host? (yes/no): ").strip().lower()
        )
        if "yes".startswith(string):
            selected_use_dhcp = True
        elif "no".startswith(string):
            selected_use_dhcp = False
    print(f"Selected use DHCP: {selected_use_dhcp}")
    return selected_use_dhcp


def get_cidr(args):
    selected_cidr = args.cidr
    while not validators.ip_address.ipv4(selected_cidr, cidr=True, strict=True):
        if selected_cidr is not None:
            print(f"{selected_cidr} is not a valid CIDR")
        print("Select IP address in CIDR format (for example '192.168.1.10/24'):")

        selected_cidr = input()
    print(f"Selected cidr: {selected_cidr}")
    return selected_cidr


def get_gateway(args):
    selected_gateway = args.gateway
    while not validators.ip_address.ipv4(selected_gateway, cidr=False):
        if selected_gateway is not None:
            print(f"{selected_gateway} is not a valid IP address")
        print("Select gateway server IP address (for example '192.168.1.10'):")

        selected_gateway = input()
    print(f"Selected gateway: {selected_gateway}")
    return selected_gateway


def get_dns(args):
    selected_dns = args.dns
    while not validators.ip_address.ipv4(selected_dns, cidr=False):
        if selected_dns is not None:
            print(f"{selected_dns} is not a valid IP address")
        print(
            "Select DNS server IP address (for example DNS4EU's protective '86.54.11.1'):"
        )

        selected_dns = input()
    print(f"Selected dns: {selected_dns}")
    return selected_dns


def command_addhost(args):
    begin_dict = {
        "domain": get_domain(args),
        "mailto": get_mailto(args),
        "keyboard": get_keyboard(args),
        "countrycode": get_countrycode(args),
        "timezone": get_timezone(args),
        "root-password-hashed": get_password(args),
    }

    addhost_dict = {
        "hostname": get_hostname(args, begin_dict["domain"]),
        "network": {"macaddress": get_macaddress(args), "use-dhcp": get_dhcp(args)},
    }

    if not addhost_dict["network"]["use-dhcp"]:
        addhost_dict["network"] = addhost_dict["network"] | {
            "cidr": get_cidr(args),
            "gateway": get_gateway(args),
            "dns": get_dns(args),
        }

    # We support running 'addhost' as the first command as well as 'begin', so we alter the global config if it's missing keys
    to_write = {}
    for k, v in begin_dict.items():
        default = get_toml_default(k)
        if default is None:
            to_write.setdefault("global", {})[k] = v
        elif v != default:
            # local override for this host
            addhost_dict[k] = v

    to_write.setdefault("host", {})[addhost_dict["hostname"]] = addhost_dict
    write_toml(to_write)


def command_unknown(args, parser):
    parser.print_usage()
    s = parser.format_usage()
    subcommands = s[s.find("{") + 1 : s.find("}")].split(",")
    subcommands_quote_string = ",".join(f"'{x}'" for x in subcommands)
    sys.exit(
        f"indie: error: argument {{{','.join(subcommands)}}}: invalid choice: '' (choose from {subcommands_quote_string})"
    )


def set_subparser_settings(subparser):
    subparser.add_argument(
        "--keyboard",
        choices=valid_keyboard_layouts,
        help="Keyboard layout to use.",
        default=get_toml_default("keyboard"),
    )
    subparser.add_argument(
        "--countrycode",
        help="ISO 3166-1 alpha 2 countrycode to use (for example DE, FR, GB, or SE). See https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2 for full list.",
        default=get_toml_default("countrycode"),
    )
    subparser.add_argument(
        "--domain",
        default=get_toml_default("domain"),
        help="Domain name to use, for example 'example.com'",
    )
    subparser.add_argument(
        "--mailto", default=get_toml_default("mailto"), help="Administrator email"
    )
    subparser.add_argument(
        "--timezone",
        default=get_toml_default("timezone"),
        help="Timezone from the IANA time zone database in the 'Area/Location' format, for example 'Europe/Stockholm'",
    )
    subparser.add_argument(
        "--root-password-hashed",
        default=get_toml_default("root-password-hashed"),
        help="SHA512 password hash, compatible with '/etc/shadow'",
    )


def main():
    # Read default values, if possible
    global indie_toml
    try:
        with open(indie_toml_file, "r", encoding="utf-8") as file:
            indie_toml = tomlkit.load(file)
    except FileNotFoundError:
        pass

    indie_toml.update({"indie":{"version":__version__}})
    parser = argparse.ArgumentParser(
        description=f"Indie Infrastructure Initiative\nVersion {__version__}\nhttps://github.com/fredrikkz/indie-infrastructure-initiative\n\nA tool to allow small indie game development studios to setup and maintain complex server infrastructure with ease",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.set_defaults(func=(lambda args, p=parser: command_unknown(args, p)))
    subparsers = parser.add_subparsers(help="Available subcommands")

    # begin
    p_begin = subparsers.add_parser(
        "begin", help="Begin the initial setup of the infrastructure"
    )
    set_subparser_settings(p_begin)
    p_begin.set_defaults(func=command_begin)

    # addhost
    p_addhost = subparsers.add_parser(
        "addhost", help="Add a new physical host machine to the infrastructure"
    )
    set_subparser_settings(p_addhost)
    p_addhost.add_argument(
        "--hostname",
        help="Hostname to use, without domain name (domain is automatically appended)",
    )
    p_addhost.add_argument(
        "--macaddress",
        help="MAC address of the physical machine",
    )
    p_addhost.add_argument(
        "--use-dhcp",
        type=bool,
        help="If true, host will use DHCP to resolve network settings",
    )
    p_addhost.add_argument(
        "--cidr",
        help="If not using DHCP, IP address in CIDR notation, for example 192.168.1.10/24",
    )
    p_addhost.add_argument(
        "--gateway",
        help="If not using DHCP, IP address of gateway server, for example 192.168.1.10",
    )
    p_addhost.add_argument(
        "--dns",
        help="If not using DHCP, IP address of DNS server, for example DNS4EU's protective 86.54.11.1",
    )
    p_addhost.set_defaults(func=command_addhost)

    args = parser.parse_args()

    args.func(args)


if __name__ == "__main__":
    main()
