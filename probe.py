"""PrivateGlue network probe.

Finds devices on the local network (ping, then name and MAC address lookup) and sends
the list to a PrivateGlue server, where an editor reviews and imports them.

Run `python probe.py --help` for the options.
"""
import argparse
import ipaddress
import os
import platform
import re
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

__version__ = "2.0.0"

API_PATH = "/api/discovered-devices"
ENV_KEY = "PRIVATEGLUE_API_KEY"
ENV_SERVER = "PRIVATEGLUE_URL"
DEFAULT_MAX_HOSTS = 1024      # a /22; larger networks need --max-hosts
DEFAULT_WORKERS = 64
# Home and office ranges (RFC 1918). Only these are scanned without being asked.
PRIVATE_BLOCKS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
MAC_RE = re.compile(r"(?<![0-9A-Fa-f])((?:[0-9A-Fa-f]{1,2}[:-]){5}[0-9A-Fa-f]{1,2})(?![0-9A-Fa-f])")
IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")


class ProbeError(Exception):
    """A problem the user can fix. The message is printed without a traceback."""


# --- which networks to scan ---------------------------------------------------

def parse_subnet(text):
    """Turn user input into a network.

    Accepts CIDR ("192.168.1.0/24", "10.0.0.5/24") and the old short form
    ("192.168.1", meaning 192.168.1.0/24).
    """
    text = (text or "").strip()
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){2}", text):
        text += ".0/24"
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise ProbeError(f"'{text}' is not a network. Use a form like 192.168.1.0/24.")
    if network.version != 4:
        raise ProbeError("Only IPv4 networks can be scanned.")
    return network


def local_networks(interfaces=None):
    """Private IPv4 networks this machine is directly connected to.

    Everything outside the home and office ranges is skipped on purpose (public addresses,
    loopback, 169.254.x.x, carrier and VPN ranges such as 100.64.x.x): the probe must never
    start scanning the internet or a provider's network by accident.
    `interfaces` is the result of psutil.net_if_addrs(); passing it in keeps this testable.
    """
    if interfaces is None:
        import psutil
        interfaces = psutil.net_if_addrs()
    found = set()
    for addrs in interfaces.values():
        for addr in addrs:
            if addr.family != socket.AF_INET or not addr.address or not addr.netmask:
                continue
            try:
                iface = ipaddress.ip_interface(f"{addr.address}/{addr.netmask}")
            except ValueError:
                continue
            if not any(iface.ip in block for block in PRIVATE_BLOCKS):
                continue
            found.add(iface.network)
    return sorted(found)


def check_size(network, max_hosts):
    hosts = max(network.num_addresses - 2, 1)
    if hosts > max_hosts:
        raise ProbeError(
            f"{network} has {hosts} addresses, more than the limit of {max_hosts}. "
            f"Scan a smaller part with --subnet, or raise the limit with --max-hosts."
        )


# --- finding devices ----------------------------------------------------------

def ping_command(ip, system=None):
    """The ping command for one echo request with a timeout of about one second."""
    system = system or platform.system()
    if system == "Windows":
        return ["ping", "-n", "1", "-w", "1000", ip]
    if system == "Darwin":
        return ["ping", "-c", "1", "-t", "1", ip]
    return ["ping", "-c", "1", "-W", "1", ip]


def ping_host(ip):
    try:
        result = subprocess.run(ping_command(ip), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=5)
    except (subprocess.TimeoutExpired, OSError):
        return False
    if result.returncode != 0:
        return False
    # Windows ping also exits with 0 when a router answers "Destination host unreachable".
    return b"unreachable" not in result.stdout.lower()


def normalize_mac(text):
    """aa:bb:cc:dd:ee:ff, or "" when the text is not a usable MAC address."""
    parts = re.split(r"[:-]", text.strip())
    if len(parts) != 6:
        return ""
    try:
        mac = ":".join(f"{int(part, 16):02x}" for part in parts)
    except ValueError:
        return ""
    if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return ""
    return mac


def parse_neighbors(text):
    """Read IP to MAC pairs from the output of `arp -a` (Windows, macOS, Linux) or
    `ip neigh` (Linux). Lines without both an IP and a MAC are ignored."""
    table = {}
    for line in text.splitlines():
        ip_match = IPV4_RE.search(line)
        mac_match = MAC_RE.search(line)
        if not ip_match or not mac_match:
            continue
        mac = normalize_mac(mac_match.group(1))
        if mac:
            table[ip_match.group(1)] = mac
    return table


def read_neighbors():
    """The operating system's neighbour (ARP) table. After a ping, it holds the MAC
    address of every device on the same network segment. Empty when it cannot be read."""
    commands = [["arp", "-a"]] if platform.system() in ("Windows", "Darwin") else [["ip", "neigh"], ["arp", "-an"]]
    for command in commands:
        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15)
        except (subprocess.TimeoutExpired, OSError):
            continue
        table = parse_neighbors(result.stdout.decode(errors="replace"))
        if table:
            return table
    return {}


def lookup_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return ""


def scan_network(network, workers=DEFAULT_WORKERS, ping=ping_host, hostname=lookup_hostname,
                 neighbors=read_neighbors):
    """Ping every address of the network at the same time and describe the ones that answer."""
    addresses = [str(ip) for ip in network.hosts()]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        alive = [ip for ip, up in zip(addresses, pool.map(ping, addresses)) if up]
        names = dict(zip(alive, pool.map(hostname, alive)))
    macs = neighbors() if alive else {}
    return [{"ip_address": ip, "hostname": names.get(ip, ""), "mac_address": macs.get(ip, "")} for ip in alive]


# --- sending the result -------------------------------------------------------

def server_url(text):
    """Accept the server address with or without the API path and return the full URL."""
    text = (text or "").strip().rstrip("/")
    if not re.match(r"^https?://[^/\s]+", text):
        raise ProbeError("The server address must start with http:// or https://, for example https://glue.example.com")
    return text if text.endswith(API_PATH) else text + API_PATH


def is_local_address(url):
    host = re.sub(r"^https?://", "", url).split("/")[0].rsplit(":", 1)[0].strip("[]")
    if host in ("localhost",):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private


def send(url, api_key, devices, verify=True, post=None):
    """POST the devices. Returns the number the server accepted, raises ProbeError otherwise."""
    import requests
    post = post or requests.post
    try:
        response = post(url, json={"devices": devices}, headers={"X-API-KEY": api_key},
                        timeout=30, verify=verify)
    except requests.exceptions.SSLError:
        raise ProbeError("The server's certificate could not be verified. Use a trusted certificate, "
                         "or add --insecure if you accept the risk on your own network.")
    except requests.exceptions.ConnectionError:
        raise ProbeError(f"Could not connect to {url}. Check the address and that this machine can reach it.")
    except requests.exceptions.Timeout:
        raise ProbeError("The server did not answer within 30 seconds.")
    except requests.exceptions.RequestException as exc:
        raise ProbeError(f"Sending failed: {type(exc).__name__}")

    if response.status_code == 401:
        raise ProbeError("The server refused the API key. Copy it again from Devices > Discovered > "
                         "Probe set-up in PrivateGlue (administrators only).")
    if response.status_code == 404:
        raise ProbeError(f"{url} does not exist on that server. Check the address.")
    if response.status_code == 413:
        raise ProbeError("The server refused the list because it is too long. Scan fewer networks at once.")
    if response.status_code == 429:
        raise ProbeError("The server is rate limiting the probe. Wait a minute and try again.")
    if response.status_code >= 400:
        raise ProbeError(f"The server answered with an error (HTTP {response.status_code}).")
    try:
        return int(response.json().get("count", len(devices)))
    except (ValueError, AttributeError, TypeError):
        raise ProbeError("The server did not answer like PrivateGlue. Check the address "
                         "(a login page or another site may be answering instead).")


# --- command line -------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        description="Find devices on the local network and send them to PrivateGlue for review.",
        epilog=f"The server address and API key can also be set with the environment variables "
               f"{ENV_SERVER} and {ENV_KEY}. Prefer {ENV_KEY} over --apikey: command lines are "
               f"visible to other users of this machine and end up in the shell history.",
    )
    parser.add_argument("--server", "--backend", dest="server", default=os.environ.get(ENV_SERVER),
                        help="PrivateGlue address, for example https://glue.example.com")
    parser.add_argument("--apikey", default=None, help=f"API key (better: set {ENV_KEY})")
    parser.add_argument("--subnet", action="append",
                        help="network to scan, for example 192.168.1.0/24. Can be given more than once. "
                             "Default: every private network this machine is connected to")
    parser.add_argument("--max-hosts", type=int, default=DEFAULT_MAX_HOSTS,
                        help=f"largest network that will be scanned (default {DEFAULT_MAX_HOSTS} addresses)")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS,
                        help=f"how many addresses are pinged at the same time (default {DEFAULT_WORKERS})")
    parser.add_argument("--dry-run", action="store_true", help="scan and print the result, send nothing")
    parser.add_argument("--insecure", action="store_true", help="do not verify the server's HTTPS certificate")
    parser.add_argument("--version", action="version", version=f"PrivateGlue probe {__version__}")
    return parser


def run(argv=None, out=print):
    args = build_parser().parse_args(argv)
    api_key = args.apikey or os.environ.get(ENV_KEY, "")

    url = None
    if not args.dry_run:
        if not args.server:
            raise ProbeError(f"No server address. Use --server https://your-privateglue or set {ENV_SERVER}. "
                             "Use --dry-run to only scan.")
        url = server_url(args.server)
        if not api_key:
            raise ProbeError(f"No API key. Set {ENV_KEY} (or use --apikey). An administrator finds the key in "
                             "PrivateGlue under Devices > Discovered > Probe set-up.")
        if url.startswith("http://") and not is_local_address(url):
            out("Warning: sending over plain http to a public address. The API key and the device list "
                "can be read by anyone on the way. Use https.")

    if not 1 <= args.workers <= 512:
        raise ProbeError("--workers must be between 1 and 512.")

    if args.subnet:
        networks = [parse_subnet(s) for s in args.subnet]
        for network in networks:
            check_size(network, args.max_hosts)
    else:
        # Found by itself: leave out the ones that are too large (a Docker or VPN adapter
        # with a /16, say) and say so, instead of refusing to scan anything.
        networks = []
        for network in local_networks():
            try:
                check_size(network, args.max_hosts)
                networks.append(network)
            except ProbeError:
                out(f"Skipping {network}: more than {args.max_hosts} addresses. "
                    f"Scan it on purpose with --subnet and --max-hosts.")
    if not networks:
        raise ProbeError("No network to scan was found on this machine. Name one with --subnet 192.168.1.0/24.")

    devices, seen = [], set()
    for network in networks:
        out(f"Scanning {network} ...")
        found = [d for d in scan_network(network, workers=args.workers) if d["ip_address"] not in seen]
        seen.update(d["ip_address"] for d in found)
        out(f"  {len(found)} device{'s' if len(found) != 1 else ''} answered.")
        devices.extend(found)

    if args.dry_run:
        for device in devices:
            out(f"  {device['ip_address']:<15}  {device['mac_address'] or '-':<17}  {device['hostname'] or '-'}")
        out(f"Dry run: {len(devices)} devices found, nothing sent.")
        return 0

    accepted = send(url, api_key, devices, verify=not args.insecure)
    out(f"Sent. PrivateGlue accepted {accepted} devices. Review them under Devices > Discovered.")
    return 0


def main(argv=None):
    try:
        return run(argv)
    except ProbeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Stopped.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
