#!/usr/bin/env python3
"""Watch Keenetic DNS proxy log for one LAN client and print new domains."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path


DEFAULT_HOST = "192.168.1.1"
DEFAULT_USER = "admin"
DEFAULT_INTERVAL = 2.0
DEFAULT_TIMEOUT = 25
DEFAULT_LOG_LINES = 300


@dataclass(frozen=True)
class DnsEvent:
    log_time: str
    request_id: str
    source_ip: str
    domain: str
    device: str
    mac: str


@dataclass
class PartialDnsEvent:
    log_time: str = ""
    source_ip: str = ""
    domain: str = ""
    device: str = "-"
    mac: str = "-"


def parse_args() -> argparse.Namespace:
    load_env_defaults()
    parser = argparse.ArgumentParser(
        description=(
            "Poll a Keenetic router log and print each new DNS domain requested "
            "by one LAN client. Requires dns-proxy debug logging on the router."
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
        "--log-lines",
        type=int,
        default=None,
        help=f"Read this many recent router log lines each poll, default: {DEFAULT_LOG_LINES}",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Print current DNS domains once and exit instead of using a startup baseline",
    )
    parser.add_argument(
        "--enable-debug",
        action="store_true",
        help="Run 'dns-proxy debug' before monitoring. This makes the router log DNS proxy details.",
    )
    parser.add_argument(
        "--include-router-lookups",
        action="store_true",
        help="Also show router-originated 127.0.0.1 DNS route refreshes if client_ip is 127.0.0.1.",
    )
    args = parser.parse_args()
    if args.env_file:
        load_env_file(Path(args.env_file), override=True)
    apply_config_defaults(args)
    return args


def main() -> int:
    args = parse_args()
    validate_ip(args.client_ip)

    if args.enable_debug:
        code, stdout, stderr = run_router_command(
            args.host, args.user, args.password, "dns-proxy debug", args.timeout
        )
        code = normalize_router_exit(code, stdout, stderr)
        if code != 0:
            print(f"failed to enable dns-proxy debug rc={code}: {brief_error(stdout, stderr)}", file=sys.stderr)
            return code

    seen_log_events: set[tuple[str, str, str, str]] = set()
    seen_domains: set[str] = set()
    stop_at = time.monotonic() + args.duration if args.duration is not None else None

    if not args.once:
        code, stdout, stderr = run_router_command(
            args.host, args.user, args.password, log_command(args.log_lines), args.timeout
        )
        code = normalize_router_exit(code, stdout, stderr)
        if code != 0:
            print(f"router command failed rc={code}: {brief_error(stdout, stderr)}", file=sys.stderr)
            return code
        for event in parse_dns_events(stdout, args.client_ip, args.include_router_lookups):
            seen_log_events.add(event_key(event))

    print_table_header()
    while True:
        code, stdout, stderr = run_router_command(
            args.host, args.user, args.password, log_command(args.log_lines), args.timeout
        )
        code = normalize_router_exit(code, stdout, stderr)
        if code != 0:
            print(f"router command failed rc={code}: {brief_error(stdout, stderr)}", file=sys.stderr)
            return code

        for event in parse_dns_events(stdout, args.client_ip, args.include_router_lookups):
            key = event_key(event)
            if key in seen_log_events:
                continue
            seen_log_events.add(key)
            if event.domain in seen_domains:
                continue
            seen_domains.add(event.domain)
            print_row(event)

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
    args.log_lines = args.log_lines if args.log_lines is not None else env_int("ROUTER_LOG_LINES", DEFAULT_LOG_LINES)


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


def log_command(log_lines: int) -> str:
    if log_lines <= 0:
        raise SystemExit(f"--log-lines must be positive: {log_lines}")
    return f"show log {log_lines} once"


def brief_error(stdout: str, stderr: str) -> str:
    text = (stderr or stdout).strip()
    if not text:
        return "-"
    lines = text.splitlines()
    if len(lines) > 8:
        text = "\n".join(lines[:4] + ["..."] + lines[-3:])
    if len(text) > 2000:
        text = text[:2000] + "\n..."
    return text


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


def parse_dns_events(text: str, client_ip: str, include_router_lookups: bool) -> list[DnsEvent]:
    partials: dict[str, PartialDnsEvent] = {}
    events: list[DnsEvent] = []

    for raw in join_log_continuations(text):
        if "ndnproxy:" not in raw:
            continue
        line = strip_ansi(raw).strip()
        header = re.search(
            r"\[(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\]\s+ndnproxy:\s+\[(?P<id>[0-9A-Fa-f]+)\]\s+(?P<body>.*)",
            line,
        )
        if not header:
            continue

        request_id = header.group("id").upper()
        event = partials.setdefault(request_id, PartialDnsEvent())
        event.log_time = header.group("time")
        body = header.group("body")

        domain_match = re.search(r"domain\s+'([^']+)'", body)
        if domain_match:
            event.domain = normalize_domain(domain_match.group(1))

        source_match = re.search(r"\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\s+to\b", body)
        if source_match:
            event.source_ip = source_match.group(1)

        device_match = re.search(r"\bdevice\s+([^,\s]+)", body)
        if device_match:
            event.device = device_match.group(1)

        mac_match = re.search(r"\bmac\s+([0-9a-f:]{17})\b", body, flags=re.I)
        if mac_match:
            event.mac = mac_match.group(1).lower()

        if event.source_ip and event.domain:
            if event.source_ip == client_ip and (include_router_lookups or event.source_ip != "127.0.0.1"):
                events.append(
                    DnsEvent(
                        log_time=event.log_time,
                        request_id=request_id,
                        source_ip=event.source_ip,
                        domain=event.domain,
                        device=event.device,
                        mac=event.mac,
                    )
                )

    return events


def join_log_continuations(text: str) -> list[str]:
    joined: list[str] = []
    current = ""
    log_start = re.compile(r"^[A-Z]\s+\[[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}\]\s+")
    for raw in text.splitlines():
        line = raw.rstrip()
        if log_start.match(line):
            if current:
                joined.append(current)
            current = line
        elif current:
            current = f"{current} {line.strip()}"
    if current:
        joined.append(current)
    return joined


def normalize_domain(value: str) -> str:
    return value.rstrip(".").lower()


def event_key(event: DnsEvent) -> tuple[str, str, str, str]:
    return event.log_time, event.request_id, event.source_ip, event.domain


def print_table_header() -> None:
    print(f"{'time':19}  {'client':15}  {'device':8}  {'mac':17}  domain", flush=True)
    print(f"{'-' * 19}  {'-' * 15}  {'-' * 8}  {'-' * 17}  {'-' * 6}", flush=True)


def print_row(event: DnsEvent) -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(
        f"{now:19}  {event.source_ip:15}  {event.device[:8]:8}  {event.mac[:17]:17}  {event.domain}",
        flush=True,
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
