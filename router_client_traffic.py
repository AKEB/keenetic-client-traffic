#!/usr/bin/env python3
"""Watch Keenetic NAT sessions for one LAN client and print new destinations."""

from __future__ import annotations

import argparse
import os
import re
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path


DEFAULT_HOST = "192.168.1.1"
DEFAULT_USER = "admin"
DEFAULT_INTERVAL = 3.0
DEFAULT_TIMEOUT = 25
DEFAULT_DNS_TIMEOUT = 1.0


@dataclass(frozen=True)
class NatSession:
    proto: str
    source_ip: str
    source_port: str
    destination_ip: str
    destination_port: str
    translated_source_ip: str


@dataclass(frozen=True)
class Interface:
    name: str
    label: str
    addresses: tuple[str, ...]


@dataclass(frozen=True)
class NetworkMap:
    address_to_interface: dict[str, Interface]
    default_interface: Interface | None


def parse_args() -> argparse.Namespace:
    load_env_defaults()
    parser = argparse.ArgumentParser(
        description=(
            "Poll a Keenetic router and print each new destination IP seen in NAT "
            "sessions for a LAN client."
        )
    )
    parser.add_argument("client_ip", help="LAN client IP address, for example 192.168.3.30")
    parser.add_argument(
        "--env-file",
        default=os.environ.get("ROUTER_ENV_FILE"),
        help="Path to .env file. Defaults to ./.env, then the script directory .env.",
    )
    parser.add_argument("--host", default=None, help="Router host/IP; overrides ROUTER_HOST")
    parser.add_argument("--user", default=None, help="Router SSH user; overrides ROUTER_USER")
    parser.add_argument("--password", default=None, help="Router SSH password; overrides ROUTER_PASSWORD")
    parser.add_argument(
        "--interval",
        type=float,
        default=None,
        help=f"Poll interval in seconds, default: {DEFAULT_INTERVAL}",
    )
    parser.add_argument(
        "--duration",
        type=float,
        help="Stop after this many seconds instead of running until interrupted",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help=f"SSH command timeout in seconds, default: {DEFAULT_TIMEOUT}",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Print current new destinations once and exit",
    )
    parser.add_argument(
        "--no-rdns",
        action="store_true",
        help="Do not try reverse DNS lookups for destination IPs",
    )
    parser.add_argument(
        "--dns-timeout",
        type=float,
        default=None,
        help=f"Reverse DNS lookup timeout in seconds, default: {DEFAULT_DNS_TIMEOUT}",
    )
    parser.add_argument(
        "--show-private",
        action="store_true",
        help="Also print private/link-local/multicast destination IPs",
    )
    args = parser.parse_args()
    if args.env_file:
        load_env_file(Path(args.env_file), override=True)
    apply_config_defaults(args)
    return args


def main() -> int:
    args = parse_args()
    validate_ip(args.client_ip)
    password = args.password
    network_map = collect_network_map(args, password)
    seen: set[str] = set()
    rdns_cache: dict[str, str] = {}
    stop_at = time.monotonic() + args.duration if args.duration is not None else None

    print_table_header()
    while True:
        code, stdout, stderr = run_router_command(
            args.host, args.user, password, "show ip nat", args.timeout
        )
        code = normalize_router_exit(code, stdout, stderr)
        if code != 0:
            print(f"router command failed rc={code}: {stderr or stdout}", file=sys.stderr)
            return code

        for session in parse_nat_sessions(stdout):
            if session.source_ip != args.client_ip:
                continue
            if session.destination_ip in seen:
                continue
            if not args.show_private and should_skip_destination(session.destination_ip):
                seen.add(session.destination_ip)
                continue

            seen.add(session.destination_ip)
            network = describe_network(session.translated_source_ip, network_map)
            domain = "-" if args.no_rdns else reverse_dns(session.destination_ip, args, rdns_cache)
            print_row(session, network, domain)

        if args.once:
            break
        if stop_at is not None and time.monotonic() >= stop_at:
            break
        sleep_for = args.interval
        if stop_at is not None:
            sleep_for = min(sleep_for, max(0.0, stop_at - time.monotonic()))
        time.sleep(sleep_for)

    return 0


def validate_ip(value: str) -> None:
    try:
        ip_address(value)
    except ValueError as exc:
        raise SystemExit(f"invalid client IP address: {value}") from exc


def load_env_defaults() -> None:
    cwd_env = Path.cwd() / ".env"
    script_env = Path(__file__).resolve().with_name(".env")
    for path in (cwd_env, script_env):
        load_env_file(path, override=False)


def load_env_file(path: Path, override: bool) -> None:
    if not path.exists():
        return

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = strip_env_value(value.strip())
        if not key or (not override and key in os.environ):
            continue
        os.environ[key] = value


def strip_env_value(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    return value


def apply_config_defaults(args: argparse.Namespace) -> None:
    args.host = args.host or os.environ.get("ROUTER_HOST", DEFAULT_HOST)
    args.user = args.user or os.environ.get("ROUTER_USER", DEFAULT_USER)
    args.password = args.password or os.environ.get("ROUTER_PASSWORD")
    args.interval = args.interval if args.interval is not None else env_float("ROUTER_INTERVAL", DEFAULT_INTERVAL)
    args.timeout = args.timeout if args.timeout is not None else env_int("ROUTER_TIMEOUT", DEFAULT_TIMEOUT)
    args.dns_timeout = (
        args.dns_timeout
        if args.dns_timeout is not None
        else env_float("ROUTER_DNS_TIMEOUT", DEFAULT_DNS_TIMEOUT)
    )


def env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise SystemExit(f"invalid integer in {name}: {value}") from exc


def env_float(name: str, default: float) -> float:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError as exc:
        raise SystemExit(f"invalid number in {name}: {value}") from exc


def run_router_command(
    host: str, user: str | None, password: str | None, command: str, timeout: int
) -> tuple[int, str, str]:
    target = host if not user else f"{user}@{host}"
    if password is None:
        proc = subprocess.run(
            ["ssh", target, command],
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, clean_expect_output(proc.stdout), proc.stderr.strip()

    expect_program = r"""
set timeout $env(ROUTER_TIMEOUT)
set password $env(ROUTER_PASSWORD)
set target $env(ROUTER_TARGET)
set command $env(ROUTER_COMMAND)
spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $target $command
expect {
    -re "(?i)yes/no" {
        send "yes\r"
        exp_continue
    }
    -re "(?i)password:" {
        send "$password\r"
        exp_continue
    }
    eof {
    }
    timeout {
        exit 124
    }
}
catch wait result
exit [lindex $result 3]
"""
    env = os.environ.copy()
    env.update(
        {
            "ROUTER_PASSWORD": password,
            "ROUTER_TARGET": target,
            "ROUTER_COMMAND": command,
            "ROUTER_TIMEOUT": str(timeout),
        }
    )
    proc = subprocess.run(
        ["/usr/bin/expect", "-c", expect_program],
        text=True,
        capture_output=True,
        timeout=timeout + 5,
        check=False,
        env=env,
    )
    return proc.returncode, clean_expect_output(proc.stdout), proc.stderr.strip()


def normalize_router_exit(code: int, stdout: str, stderr: str) -> int:
    combined = f"{stdout}\n{stderr}".lower()
    if "operation not permitted" in combined:
        return 126
    if "permission denied" in combined:
        return 255
    if "could not resolve hostname" in combined:
        return 68
    if "connection refused" in combined:
        return 111
    if "timed out" in combined:
        return 124
    return code


def clean_expect_output(text: str) -> str:
    lines = []
    for line in text.splitlines():
        line = strip_ansi(line).rstrip()
        if line.startswith("spawn ssh "):
            continue
        if re.search(r"@.+password:", line):
            continue
        if "WARNING: connection is not using a post-quantum" in line:
            continue
        if "store now, decrypt later" in line:
            continue
        if "https://openssh.com/pq.html" in line:
            continue
        lines.append(line)
    return "\n".join(lines).strip()


def strip_ansi(value: str) -> str:
    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", value)


def collect_network_map(args: argparse.Namespace, password: str | None) -> NetworkMap:
    commands = ("show interface", "show running-config", "show ip route")
    outputs = []
    for command in commands:
        code, stdout, stderr = run_router_command(args.host, args.user, password, command, args.timeout)
        code = normalize_router_exit(code, stdout, stderr)
        if code != 0:
            print(f"warning: {command!r} failed rc={code}: {stderr or stdout}", file=sys.stderr)
            outputs.append("")
        else:
            outputs.append(stdout)

    interfaces = parse_interfaces(outputs[0])
    enrich_interfaces_from_config(interfaces, outputs[1])
    default_interface = parse_default_interface(outputs[2], interfaces)
    by_address: dict[str, Interface] = {}
    for iface in interfaces.values():
        for address in iface.addresses:
            by_address[address] = iface
    return NetworkMap(address_to_interface=by_address, default_interface=default_interface)


def parse_default_interface(text: str, interfaces: dict[str, Interface]) -> Interface | None:
    for raw in text.splitlines():
        line = strip_ansi(raw).strip()
        if "0.0.0.0/0" not in line and not re.search(r"\bdefault\b", line, re.I):
            continue

        match = re.search(r"\bdev\s+([A-Za-z][\w.\-/]*)", line)
        if not match:
            columns = re.split(r"\s{2,}", line)
            if len(columns) >= 3 and columns[0] == "0.0.0.0/0":
                match = re.match(r"([A-Za-z][\w.\-/]*)", columns[2])
        if not match:
            continue

        name = match.group(1)
        return interfaces.get(name, Interface(name=name, label=name, addresses=()))
    return None


def parse_interfaces(text: str) -> dict[str, Interface]:
    names: dict[str, str] = {}
    addresses: dict[str, set[str]] = {}
    current: str | None = None

    for raw in text.splitlines():
        line = strip_ansi(raw).strip()
        header = re.match(r'^Interface,\s+name\s+=\s+"?([^"]+)"?$', line, flags=re.I)
        if header:
            current = header.group(1)
            names.setdefault(current, current)
            addresses.setdefault(current, set())
            continue

        table = parse_interface_table_line(line)
        if table:
            name, ips = table
            names.setdefault(name, name)
            addresses.setdefault(name, set()).update(ips)
            current = None
            continue

        if current is None:
            continue
        address = re.match(r"^address:\s+(\d{1,3}(?:\.\d{1,3}){3})\b", line, flags=re.I)
        if address:
            addresses.setdefault(current, set()).add(address.group(1))

    return {
        name: Interface(name=name, label=name, addresses=tuple(sorted(ips)))
        for name, ips in addresses.items()
    }


def parse_interface_table_line(line: str) -> tuple[str, list[str]] | None:
    parts = re.split(r"\s{2,}", line.strip())
    if len(parts) < 2 or parts[0].lower() in {"interface", "name"}:
        return None
    name = parts[0].strip()
    if not re.match(r"^[A-Za-z][\w.\-/]*\d*$", name):
        return None
    ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line)
    return name, ips


def enrich_interfaces_from_config(interfaces: dict[str, Interface], text: str) -> None:
    current: str | None = None
    descriptions: dict[str, str] = {}
    config_addresses: dict[str, set[str]] = {}

    for raw in text.splitlines():
        line = strip_ansi(raw).strip()
        match = re.match(r"^interface\s+(.+)$", line, flags=re.I)
        if match:
            current = match.group(1).strip()
            config_addresses.setdefault(current, set())
            continue
        if current is None:
            continue
        if line == "!":
            current = None
            continue
        desc = re.match(r"^description\s+(.+)$", line, flags=re.I)
        if desc:
            descriptions[current] = desc.group(1).strip().strip('"')
            continue
        address = re.match(r"^ip\s+address\s+(\d{1,3}(?:\.\d{1,3}){3})\b", line, flags=re.I)
        if address:
            config_addresses.setdefault(current, set()).add(address.group(1))

    for name, ips in config_addresses.items():
        existing = interfaces.get(name)
        label = descriptions.get(name, existing.label if existing else name)
        merged = set(existing.addresses if existing else ())
        merged.update(ips)
        interfaces[name] = Interface(name=name, label=label, addresses=tuple(sorted(merged)))

    for name, description in descriptions.items():
        existing = interfaces.get(name)
        if existing:
            interfaces[name] = Interface(
                name=existing.name,
                label=description,
                addresses=existing.addresses,
            )


def parse_nat_sessions(text: str) -> list[NatSession]:
    sessions: list[NatSession] = []
    lines = [strip_ansi(line).rstrip() for line in text.splitlines()]
    i = 0
    while i < len(lines):
        first = parse_nat_first_line(lines[i])
        if first is None:
            i += 1
            continue
        if i + 1 >= len(lines):
            break
        second = parse_nat_second_line(lines[i + 1])
        if second is None:
            i += 1
            continue

        proto, src_ip, src_port, dst_ip, dst_port = first
        translated_source_ip = second[2]
        sessions.append(
            NatSession(
                proto=proto,
                source_ip=src_ip,
                source_port=src_port,
                destination_ip=dst_ip,
                destination_port=dst_port,
                translated_source_ip=translated_source_ip,
            )
        )
        i += 2
    return sessions


def parse_nat_first_line(line: str) -> tuple[str, str, str, str, str] | None:
    parts = line.split()
    if len(parts) < 6:
        return None
    proto = parts[0]
    if proto not in {"TCP", "UDP", "ICMP"}:
        return None
    if not is_ip(parts[1]) or not parts[2].isdigit() or not is_ip(parts[3]):
        return None
    return proto, parts[1], parts[2], parts[3], parts[4]


def parse_nat_second_line(line: str) -> tuple[str, str, str, str] | None:
    parts = line.split()
    if len(parts) < 4:
        return None
    if not is_ip(parts[0]) or not parts[1].isdigit() or not is_ip(parts[2]):
        return None
    return parts[0], parts[1], parts[2], parts[3]


def is_ip(value: str) -> bool:
    try:
        ip_address(value)
    except ValueError:
        return False
    return True


def should_skip_destination(value: str) -> bool:
    parsed = ip_address(value)
    return parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_multicast


def describe_network(translated_source_ip: str, network_map: NetworkMap) -> str:
    iface = network_map.address_to_interface.get(translated_source_ip)
    if iface is not None:
        if (
            network_map.default_interface is not None
            and iface.name == network_map.default_interface.name
            and ip_address(translated_source_ip).is_global
        ):
            return f"Direct / {format_interface_label(iface)}"
        return format_interface_label(iface)

    parsed = ip_address(translated_source_ip)
    if parsed.is_global:
        if network_map.default_interface is not None:
            return f"Direct / {format_interface_label(network_map.default_interface)}"
        return f"Direct / WAN ({translated_source_ip})"
    return translated_source_ip


def format_interface_label(iface: Interface) -> str:
    if iface.label and iface.label != iface.name:
        return f"{iface.label} ({iface.name})"
    return iface.name


def reverse_dns(destination_ip: str, args: argparse.Namespace, cache: dict[str, str]) -> str:
    if destination_ip in cache:
        return cache[destination_ip]

    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(args.dns_timeout)
    try:
        domain = socket.gethostbyaddr(destination_ip)[0].rstrip(".")
    except (OSError, socket.herror, socket.gaierror, TimeoutError):
        domain = "-"
    finally:
        socket.setdefaulttimeout(old_timeout)

    cache[destination_ip] = domain
    return domain


def print_table_header() -> None:
    print(
        f"{'time':19}  {'proto':5}  {'destination':15}  {'port':5}  {'via':36}  domain",
        flush=True,
    )
    print(
        f"{'-' * 19}  {'-' * 5}  {'-' * 15}  {'-' * 5}  {'-' * 36}  {'-' * 6}",
        flush=True,
    )


def print_row(session: NatSession, network: str, domain: str) -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(
        f"{now:19}  {session.proto:5}  {session.destination_ip:15}  "
        f"{session.destination_port:5}  {network[:36]:36}  {domain}",
        flush=True,
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
