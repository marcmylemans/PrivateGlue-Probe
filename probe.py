import subprocess
import socket
import requests
import json
import ipaddress
import psutil
import argparse

def get_all_subnet_prefixes():
    prefixes = set()
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                ip = addr.address
                netmask = addr.netmask
                if ip and netmask:
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    prefix = str(network.network_address).rsplit('.', 1)[0]
                    prefixes.add(prefix)
    return list(prefixes)

def ping_host(ip):
    result = subprocess.run(['ping', '-n', '1', '-w', '100', ip], stdout=subprocess.DEVNULL)
    return result.returncode == 0

def scan_subnet(subnet_prefix):
    devices = []
    for i in range(1, 255):
        ip = f"{subnet_prefix}.{i}"
        if ping_host(ip):
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = ""
            devices.append({
                "ip_address": ip,
                "hostname": hostname,
                "mac_address": "",
                "device_type": "",
                "operating_system": "",
                "os_version": "",
                "serial_number": "",
                "license_key": "",
                "location": ""
            })
    return devices

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network probe for device discovery.")
    parser.add_argument('--subnet', type=str, help='Subnet prefix to scan (e.g. 192.168.1)')
    parser.add_argument('--backend', type=str, default='http://localhost:5000/api/discovered-devices', help='Backend URL to POST results')
    parser.add_argument('--apikey', type=str, help='API key for authentication with backend')
    args = parser.parse_args()

    if args.subnet:
        subnets = [args.subnet]
    else:
        subnets = get_all_subnet_prefixes()
        if not subnets:
            print("Could not auto-detect any subnets. Please specify with --subnet.")
            exit(1)

    all_devices = []
    for subnet_prefix in subnets:
        print(f"Scanning subnet {subnet_prefix}.0/24 ...")
        devices = scan_subnet(subnet_prefix)
        print(f"Found {len(devices)} devices on {subnet_prefix}.0/24.")
        all_devices.extend(devices)

    headers = {}
    if args.apikey:
        headers["X-API-KEY"] = args.apikey
    print(f"Sending {len(all_devices)} devices to backend {args.backend} ...")
    resp = requests.post(args.backend, json={"devices": all_devices}, headers=headers)
    print("Backend response:", resp.json())