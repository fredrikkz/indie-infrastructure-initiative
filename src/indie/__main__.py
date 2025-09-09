#!/usr/bin/env python3

import os
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
import datetime
import ssl
import uuid
import math
import importlib
from aiohttp import web
from zoneinfo import available_timezones
from passlib.hash import sha512_crypt
from pathlib import Path
from . import __version__
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import hashes

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

indie_root_dir = Path.cwd() / ".indie"
indie_toml_file = indie_root_dir / "indie.toml"
indie_toml = tomlkit.document()

private_key_pem_file = indie_root_dir / "private_key.pem"
cert_pem_file = indie_root_dir / "cert.pem"

private_key_ssh_file = indie_root_dir / "id_ed25519"
public_key_ssh_file = indie_root_dir / "id_ed25519.pub"


def write_toml(data: dict):
    indie_toml.update(data)

    indie_toml_file.parent.mkdir(parents=True, exist_ok=True)
    with open(indie_toml_file, "w", encoding="utf-8") as file:
        file.write(indie_toml.as_string())


def get_proxmox_toml(mac):
    toml_dict = indie_toml.unwrap()
    for host in toml_dict.get("host", []):
        if host["macaddress"] != mac:
            continue

        domain = toml_dict["global"].pop("domain")
        token = toml_dict["global"].pop("https-access-token")
        fingerprint = toml_dict["global"].pop("cert-fingerprint")
        to_write = {"global": toml_dict["global"]}
        to_write["global"]["fqdn"] = host["hostname"] + "." + domain

        to_write["network"] = (
            {"source": "from-dhcp"}
            if host["use-dhcp"]
            else {
                "source": "from-answer",
                "cidr": host["cidr"],
                "dns": host["dns"],
                "gateway": host["gateway"],
                tomlkit.key(["filter", "ID_NET_NAME_MAC"]): f"*{mac.replace(':','')}",
            }
        )

        # TODO: Improve on this
        if host["use-raid1"]:
            to_write["disk-setup"] = {
                "disk-list": ["sda", "sdb", "sdc", "sdd", "sde", "sdf"],
                "filesystem": "zfs",
                tomlkit.key(["zfs", "raid"]): "raid1",
            }
        else:
            to_write["disk-setup"] = {
                "disk-list": ["sda"],
                "filesystem": "ext4",
            }

        to_write["first-boot"] = {
            "source": "from-url",
            "url": f"https://indie.{domain}:8000/getscript?token={token}&script=first_boot_wrapper.sh",
            "cert-fingerprint": fingerprint,
        }

        to_write["post-installation-webhook"] = {
            "url": f"https://indie.{domain}:8000/proxmox-post-install?token={token}",
            "cert-fingerprint": fingerprint,
        }

        proxmox_toml = tomlkit.document()
        proxmox_toml.update(to_write)
        return proxmox_toml
    return None


def get_toml_default(key, table="global"):
    try:
        return indie_toml[table][key]
    except KeyError:
        return None


def generate_cert_and_ssh_keys_if_not_present():
    if private_key_pem_file.is_file() and cert_pem_file.is_file():
        with open(private_key_pem_file, "rb") as file:
            private_key = serialization.load_pem_private_key(file.read(), None)
        with open(cert_pem_file, "rb") as file:
            cert = x509.load_pem_x509_certificate(file.read())
    else:
        private_key = ed25519.Ed25519PrivateKey.generate()
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, get_toml_default("country")),
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, get_toml_default("mailto")),
                x509.NameAttribute(
                    NameOID.LOCALITY_NAME,
                    get_toml_default("timezone").split("/")[1].replace("_", " "),
                ),
                x509.NameAttribute(NameOID.COMMON_NAME, get_toml_default("domain")),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(
                # Our certificate will be valid for 100 years
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=365 * 100)
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(get_toml_default("domain"))]),
                critical=False,
            )
            .sign(private_key, None)
        )

        private_key_pem_file.parent.mkdir(parents=True, exist_ok=True)
        with open(private_key_pem_file, "wb") as file:
            file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        cert_pem_file.parent.mkdir(parents=True, exist_ok=True)
        with open(cert_pem_file, "wb") as file:
            file.write(cert.public_bytes(serialization.Encoding.PEM))

    private_key_ssh_file.parent.mkdir(parents=True, exist_ok=True)
    with open(private_key_ssh_file, "wb") as file:
        file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.OpenSSH,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    public_key_ssh_file.parent.mkdir(parents=True, exist_ok=True)
    with open(public_key_ssh_file, "wb") as file:
        file.write(
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH,
            )
        )

    fingerprint = cert.fingerprint(hashes.SHA256())
    to_write = indie_toml.unwrap()
    to_write["global"]["cert-fingerprint"] = fingerprint.hex(":")
    with open(public_key_ssh_file, "r") as file:
        to_write["global"]["root-ssh-keys"] = [file.read()]
    write_toml(to_write)


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


def get_country(args):
    selected_country = str(args.country or "")
    while pycountry.countries.get(alpha_2=selected_country) is None:
        if selected_country != "":
            print(f"{selected_country} is not a valid countrycode")
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

        selected_country = str(input() or "")
        if selected_country == "" and do_suggest:
            selected_country = g.country

    print(f"Selected countrycode: {selected_country}")
    return selected_country.lower()


def get_domain(args):
    selected_domain = args.domain
    while not validators.domain(selected_domain):
        if selected_domain is not None:
            print(f"{selected_domain} is not a valid domain")
        print("Select domain (for example, 'example.com'):")

        selected_domain = input()
    print(f"Selected domain: {selected_domain}")
    return selected_domain.lower()


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
            continue

    print(f"Selected password hash: {selected_password}")
    return selected_password


def get_https_access_token(args):
    selected_https_access_token = args.https_access_token
    while not validators.uuid(selected_https_access_token):
        selected_https_access_token = str(uuid.uuid4())
    print(f"Selected https_access_token: {selected_https_access_token}")
    return selected_https_access_token.lower()


def command_begin(args):
    begin_dict = {
        "domain": get_domain(args),
        "mailto": get_mailto(args),
        "keyboard": get_keyboard(args),
        "country": get_country(args),
        "timezone": get_timezone(args),
        "root-password-hashed": get_password(args),
        "https-access-token": get_https_access_token(args),
    }
    write_toml(
        {"global": begin_dict},
    )
    generate_cert_and_ssh_keys_if_not_present()


def is_hostproperty_in_use(prop, cmp):
    data = indie_toml.unwrap()
    for d in data.get("host", []):
        if d[prop] == cmp:
            return True
    return False


def get_hostname(args, domain):
    selected_hostname = args.hostname
    while not validators.domain(
        (selected_hostname or "") + "." + domain
    ) or is_hostproperty_in_use("hostname", selected_hostname):
        if selected_hostname is not None:
            if not validators.domain((selected_hostname or "") + "." + domain):
                print(f"{selected_hostname + '.' + domain} is not a valid domain")
            elif is_hostproperty_in_use("hostname", selected_hostname):
                print(f"'{selected_hostname}' already in use")
        print("Select hostname:")

        selected_hostname = input()
    print(
        f"Selected hostname: {selected_hostname}, FQDN becomes '{selected_hostname + '.' + domain}'"
    )
    return selected_hostname


def get_macaddress(args):
    selected_macaddress = args.macaddress
    while not validators.mac_address(selected_macaddress) or is_hostproperty_in_use(
        "macaddress", selected_macaddress
    ):
        if selected_macaddress is not None:
            if not validators.mac_address(selected_macaddress):
                print(f"{selected_macaddress} is not a valid MAC address")
            elif is_hostproperty_in_use("macaddress", selected_macaddress):
                print(f"'{selected_macaddress}' already in use")
        print("Select MAC address:")

        selected_macaddress = input()
    print(f"Selected MAC address: {selected_macaddress}")
    return selected_macaddress.lower()


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
        print(
            "Select static IP address in CIDR format (for example '192.168.0.123/24'):"
        )

        selected_cidr = input()
    print(f"Selected cidr: {selected_cidr}")
    return selected_cidr


def get_gateway(args):
    selected_gateway = args.gateway
    while not validators.ip_address.ipv4(selected_gateway, cidr=False):
        if selected_gateway is not None:
            print(f"{selected_gateway} is not a valid IP address")
        print("Select gateway server IP address (for example '192.168.0.1'):")

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


def get_raid(args):
    selected_use_raid = args.use_raid1
    while not isinstance(selected_use_raid, bool):
        string = (
            input("Do you want to use RAID1 for this host? (yes/no): ").strip().lower()
        )
        if "yes".startswith(string):
            selected_use_raid = True
        elif "no".startswith(string):
            selected_use_raid = False
    print(f"Selected use RAID1: {selected_use_raid}")
    return selected_use_raid


def get_internal_ip(args):
    selected_internal_ip = args.internal_ip
    to_test = 0
    while not validators.ip_address.ipv4(
        selected_internal_ip, cidr=False
    ) or is_hostproperty_in_use("internal-ip", selected_internal_ip):
        to_test = to_test + 1
        major = math.trunc(to_test / 256)
        minor = to_test - major * 256
        selected_internal_ip = f"10.111.{major}.{minor}"

    print(f"Selected internal IP: {selected_internal_ip}")
    return selected_internal_ip


def command_addhost(args):
    begin_dict = {
        "domain": get_domain(args),
        "mailto": get_mailto(args),
        "keyboard": get_keyboard(args),
        "country": get_country(args),
        "timezone": get_timezone(args),
        "root-password-hashed": get_password(args),
        "https-access-token": get_https_access_token(args),
    }

    addhost_dict = {
        "hostname": get_hostname(args, begin_dict["domain"]),
        "macaddress": get_macaddress(args),
        "use-dhcp": get_dhcp(args),
        "use-raid1": get_raid(args),
        "internal-ip": get_internal_ip(args),
    }

    if not addhost_dict["use-dhcp"]:
        addhost_dict = addhost_dict | {
            "cidr": get_cidr(args),
            "gateway": get_gateway(args),
            "dns": get_dns(args),
        }

    # We support running 'addhost' as the first command as well as 'begin', so we alter the global config if it's missing keys
    to_write = indie_toml.unwrap()
    for k, v in begin_dict.items():
        default = to_write.get("global", {}).get(k)
        if default is None:
            to_write.setdefault("global", {})[k] = v
        elif v != default:
            # local override for this host
            addhost_dict[k] = v

    to_write.setdefault("host", []).append(addhost_dict)
    write_toml(to_write)
    generate_cert_and_ssh_keys_if_not_present()


def getscript(script):
    try:
        text = importlib.resources.read_text("indie.script", script, errors="strict")

        # TODO begin: Fix this mess, convert from TOML instead
        mailto = get_toml_default("mailto")
        token = get_toml_default("https-access-token")
        domain = get_toml_default("domain")
        api = get_toml_default("api", "acme")
        iso_name = "proxmox-ve_9.0-1"
        fingerprint = get_toml_default("cert-fingerprint")
        if api is None:
            api = ""
        else:
            api_data = get_toml_default("api-data", "acme")
            api = f"""
report_progress "Registering 'indie' ACME account (TODO: add cluster support)..."
echo "y" | setsid pvenode acme account register indie {mailto} --directory "https://acme-v02.api.letsencrypt.org/directory"
echo "{api_data}" > ~/indie_plugin_dns_data
pvenode acme plugin add dns indie_plugin --api {api} --data ~/indie_plugin_dns_data
pvenode acme plugin config indie_plugin
pvenode config set --acme account=indie -acmedomain0 $hostname.{domain},plugin=indie_plugin
pvenode acme cert order
"""
        # TODO end

        to_replace = {
            "token": token,
            "domain": domain,
            "api": api,
            "mailto": mailto,
            "iso_name": iso_name,
            "fingerprint": fingerprint,
        }

        return text.format(**to_replace)
    except Exception as e:
        print(e)
        return None
    return text


def command_getscript(args):
    if args.script is None:
        print(f"Available scripts:")
        for f in importlib.resources.files("indie.script").iterdir():
            if not f.is_file():
                continue
            print(f.name)
        return

    script_content = getscript(args.script)
    if script_content is None:
        sys.exit(f"indie: error: unable to find '{args.script}'")

    if args.print:
        print(script_content)
        return

    filename = args.script if args.file is None else args.file
    try:
        with open(filename, "w", encoding="utf-8") as file:
            file.write(script_content)
    except Exception as e:
        sys.exit(f"indie: error: unable to write to file '{filename}'\n{e}")


def command_serve(args):
    routes = web.RouteTableDef()
    token = get_toml_default("https-access-token")
    print(f"Serving requests for {token}...")

    @routes.post("/proxmox-answer")
    async def proxmox_answer(request: web.Request):
        if request.query.get("token", "") != token:
            return web.Response(
                status=401,
                text=f"Unauthorized",
            )
        try:
            request_data = json.loads(await request.text())
        except json.JSONDecodeError as e:
            return web.Response(
                status=500,
                text=f"Internal Server Error: failed to parse request contents: {e}",
            )

        print(
            f"Request data for peer '{request.remote}':\n"
            f"{json.dumps(request_data, indent=2)}"
        )

        macs_tried = []
        for nic in request_data.get("network_interfaces", []):
            if "mac" not in nic:
                continue
            mac = nic["mac"].lower()
            macs_tried.append(mac)
            proxmox_toml = get_proxmox_toml(mac)
            if proxmox_toml is not None:
                answer = tomlkit.dumps(proxmox_toml)
                print(
                    f"Answer file for peer '{request.remote}':\n===BOF===\n{answer}\n===EOF==="
                )
                return web.Response(text=answer)

        message = f"Failed to find toml for any of the following MAC addresses: {', '.join(map(str, macs_tried))}"

        print(message)
        return web.Response(status=500, text=f"Internal Server Error: {message}")

    @routes.get("/getscript")
    async def web_getscript(request: web.Request):
        if request.query.get("token", "") != token:
            return web.Response(
                status=401,
                text=f"Unauthorized",
            )
        script_content = getscript(request.query.get("script", ""))
        if script_content is None:
            return web.Response(
                status=404,
                text=f"Not Found",
            )
        return web.Response(text=script_content)

    @routes.get("/get-info")
    async def get_info(request: web.Request):
        if request.query.get("token", "") != token:
            return web.Response(
                status=401,
                text=f"Unauthorized",
            )
        print(f"Request get-info data for peer '{request.remote}':")

        hostname = request.query.get("hostname")
        attribute = request.query.get("attribute")

        toml_dict = indie_toml.unwrap()
        for host in toml_dict.get("host", []):
            if host["hostname"] != hostname:
                continue
            if attribute in host:
                ret = host[attribute]
                print(f"Returning '{ret}' for '{hostname}/{attribute}'...")
                return web.Response(text=host[attribute])
        return web.Response(
            status=404,
            text=f"Not Found",
        )

    @routes.post("/proxmox-post-install")
    async def proxmox_post_install(request: web.Request):
        if request.query.get("token", "") != token:
            return web.Response(
                status=401,
                text=f"Unauthorized",
            )
        try:
            request_data = json.loads(await request.text())
        except json.JSONDecodeError as e:
            return web.Response(
                status=500,
                text=f"Internal Server Error: failed to parse request contents: {e}",
            )

        print(
            f"Request proxmox-post-install data for peer '{request.remote}':\n"
            f"{json.dumps(request_data, indent=2)}\n"
            f"Installation reported complete for {request_data.get('fqdn','')}, about to reboot"
        )

        return web.Response(text="Proxmox post-install message received")

    @routes.post("/report-progress")
    async def report_progress(request: web.Request):
        if request.query.get("token", "") != token:
            return web.Response(
                status=401,
                text=f"Unauthorized",
            )
        try:
            request_data = json.loads(await request.text())
        except json.JSONDecodeError as e:
            return web.Response(
                status=500,
                text=f"Internal Server Error: failed to parse request contents: {e}",
            )

        print(f"{request_data.get('hostname','')}: {request_data.get('message','')}")
        return web.Response(text="Report-progress message received")

    app = web.Application()
    app.add_routes(routes)
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(cert_pem_file, private_key_pem_file)
    web.run_app(app, port=8000, ssl_context=ssl_context)


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
        "--country",
        help="ISO 3166-1 alpha 2 countrycode to use (for example DE, FR, GB, or SE). See https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2 for full list.",
        default=get_toml_default("country"),
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
    subparser.add_argument(
        "--https-access-token",
        default=get_toml_default("https-access-token"),
        help="A UUID to limit access to the https webserver when running 'indie serve'",
    )


def main():
    # Read default values, if possible
    global indie_toml
    try:
        with open(indie_toml_file, "r", encoding="utf-8") as file:
            indie_toml = tomlkit.load(file)
    except FileNotFoundError:
        pass

    indie_toml.update({"indie": {"version": __version__}})
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
        help="If not using DHCP, static IP address of the host in CIDR notation, for example 192.168.0.123/24.",
    )
    p_addhost.add_argument(
        "--gateway",
        help="If not using DHCP, IP address of gateway server, for example 192.168.0.1",
    )
    p_addhost.add_argument(
        "--dns",
        help="If not using DHCP, IP address of DNS server, for example DNS4EU's protective 86.54.11.1",
    )
    p_addhost.add_argument(
        "--use-raid1",
        type=bool,
        help="If true, use RAID1 (requires multiple harddrives or install of host will fail)",
    )
    p_addhost.add_argument(
        "--internal-ip",
        help="Internal IP of host, in the 'indie' virtual bridge, expected to be on the form 10.111.XXX.YYY",
    )
    p_addhost.set_defaults(func=command_addhost)

    # serve
    p_serve = subparsers.add_parser(
        "serve",
        help="Starts a webserver, serving setup scripts",
    )
    p_serve.set_defaults(func=command_serve)

    # getscript
    p_getscript = subparsers.add_parser(
        "getscript",
        help="Writes a script to file or prints it to stdout",
    )
    p_getscript.add_argument(
        "-p",
        "--print",
        action="store_true",
        help="If set, prints to 'stdout' instead of writing to file",
    )
    p_getscript.add_argument(
        "-f",
        "--file",
        help="If set, saves to 'file' instead of script name",
    )
    p_getscript.add_argument(
        "-s",
        "--script",
        help="Name of script to get. If omitted, list all available scripts instead",
    )
    p_getscript.set_defaults(func=command_getscript)

    args = parser.parse_args()

    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\n")


if __name__ == "__main__":
    main()
