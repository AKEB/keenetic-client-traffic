# Keenetic Client Watchers

Standalone scripts for watching one LAN client on a Keenetic router.

- `router_client_traffic.py` watches active NAT sessions and shows destination IP, port, and outgoing network/VPN.
- `router_client_dns.py` watches Keenetic DNS proxy debug log and shows domains requested by the client.

`router_client_traffic.py` prints each destination IP only once per run:

```bash
./router_client_traffic.py 192.168.3.30 --duration 20 --no-rdns
```

`router_client_dns.py` prints each DNS domain only once per run:

```bash
./router_client_dns.py 192.168.3.30 --duration 60 --enable-debug
```

## Setup

Requirements:

- Python 3
- `ssh`
- `expect` if using password auth

Copy `.env.example` to `.env` and edit:

```bash
cp .env.example .env
chmod +x router_client_traffic.py
chmod +x router_client_dns.py
```

Example `.env`:

```dotenv
ROUTER_HOST=192.168.1.1
ROUTER_USER=admin
ROUTER_PASSWORD=your-router-password
ROUTER_INTERVAL=3
ROUTER_TIMEOUT=25
ROUTER_DNS_TIMEOUT=1
ROUTER_LOG_LINES=300
```

The script looks for `.env` in the current directory first, then next to the script. You can also pass a custom file:

```bash
./router_client_traffic.py 192.168.3.30 --env-file /path/to/router.env
```

## Output

Traffic columns:

- `destination`: destination IP
- `port`: destination port
- `via`: router interface/network used, such as `vpn-de (Wireguard0)`, `vpn-goga (Wireguard2)`, or `Direct / ISP`
- `domain`: reverse DNS name if known; use `--no-rdns` to skip lookups

DNS columns:

- `client`: LAN client IP that asked the router DNS proxy
- `device`: Keenetic internal device id if present in the log
- `mac`: client MAC if present in the log
- `domain`: requested DNS name

DNS monitoring requires `dns-proxy debug` on the router. Pass `--enable-debug` to enable it before monitoring. The first poll is used as a baseline, so old log entries are not printed; only domains that appear while the script is running are shown. Use `--once` if you want to print matching domains already present in the current log.

The DNS watcher reads `show log 300 once` by default. If the router is very busy, increase or decrease this window with `--log-lines` or `ROUTER_LOG_LINES`.

Useful examples:

```bash
./router_client_traffic.py 192.168.3.30 --duration 60
./router_client_traffic.py 192.168.3.30 --duration 60 --no-rdns --interval 2
./router_client_traffic.py 192.168.3.30 --once --show-private
./router_client_dns.py 192.168.3.30 --duration 60 --enable-debug
./router_client_dns.py 192.168.3.30 --duration 60 --interval 1
./router_client_dns.py 192.168.3.30 --duration 60 --log-lines 600
./router_client_dns.py 192.168.3.30 --once
```
