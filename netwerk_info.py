"""Read-only local-network discovery helpers for Network Monitor.

The scanner is intentionally limited to the connected IPv4 LAN.  It uses ARP,
ICMP and a small TCP service check; it never changes router or device state.
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import os
import re
import socket
import subprocess
import time
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KNOWN_DEVICES_FILE = os.path.join(BASE_DIR, "Known_devices.json")
HISTORY_FILE = os.path.join(BASE_DIR, "scan_history.json")
DEVICE_HISTORY_FILE = os.path.join(BASE_DIR, "device_history.json")

COMMON_PORTS = [21, 22, 23, 53, 80, 443, 139, 445, 554, 3389]
PORT_NAMES = {21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP", 443: "HTTPS", 139: "NetBIOS", 445: "SMB", 554: "RTSP", 3389: "Remote Desktop"}
PORT_SECURITY = {21: "WARNING", 22: "INFO", 23: "WARNING", 53: "INFO", 80: "INFO", 443: "OK", 139: "INFO", 445: "WARNING", 554: "INFO", 3389: "WARNING"}

# A compact offline OUI map. Unknown vendors remain explicitly unknown rather
# than pretending a device can be identified with certainty.
MAC_VENDORS = {
    "00-03-93": "Apple", "00-0A-27": "Apple", "3C-22-FB": "Apple", "40-6C-8F": "Apple", "48-60-BC": "Apple", "98-25-4A": "Apple", "A4-83-E7": "Apple", "B8-E9-37": "Apple", "F0-18-98": "Apple",
    "00-50-F2": "Microsoft", "28-18-78": "Microsoft", "7C-ED-8D": "Microsoft", "F0-6E-0B": "Microsoft",
    "00-1D-0F": "Sony", "00-24-8D": "Sony", "AC-9B-0A": "Sony", "00-09-BF": "Nintendo", "00-1F-32": "Nintendo",
    "00-12-47": "Samsung", "00-16-32": "Samsung", "34-23-BA": "Samsung", "CC-07-AB": "Samsung",
    "00-27-19": "TP-Link", "50-C7-BF": "TP-Link", "60-32-B1": "TP-Link", "98-DE-D0": "TP-Link",
    "00-14-6C": "Netgear", "20-4E-7F": "Netgear", "A0-40-A0": "Netgear", "00-14-22": "Dell", "18-03-73": "Dell", "B8-CA-3A": "Dell",
    "00-09-2D": "Lenovo", "54-EE-75": "Lenovo", "98-FA-B0": "Lenovo", "00-1E-0B": "HP", "3C-4A-92": "HP", "B4-B5-2F": "HP",
    "00-1A-92": "ASUS", "10-BF-48": "ASUS", "AC-22-0B": "ASUS", "B8-27-EB": "Raspberry Pi", "DC-A6-32": "Raspberry Pi", "E4-5F-01": "Raspberry Pi",
}


def _run(command: list[str], timeout: float = 5) -> str:
    try:
        return subprocess.check_output(command, text=True, encoding="utf-8", errors="ignore", timeout=timeout, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return ""


def normalize_mac(mac: str | None) -> str | None:
    if not mac or mac.lower() == "unknown":
        return None
    value = mac.upper().replace(":", "-").replace(".", "-")
    return value if re.fullmatch(r"[0-9A-F]{2}(?:-[0-9A-F]{2}){5}", value) else None


def is_private_mac(mac: str | None) -> bool:
    value = normalize_mac(mac)
    return bool(value and int(value[:2], 16) & 2)


def get_vendor(mac: str | None) -> str:
    value = normalize_mac(mac)
    if not value:
        return "Unknown"
    if is_private_mac(value):
        return "Private / Randomized MAC"
    return MAC_VENDORS.get(value[:8], "Unknown")


def get_ip_address() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        try:
            connection.connect(("8.8.8.8", 80))
            return connection.getsockname()[0]
        except OSError:
            return "Unknown"


def get_network_cidr() -> str:
    ip = get_ip_address()
    # Most home networks are /24. Ask Windows for the actual prefix when it is available.
    output = _run(["powershell", "-NoProfile", "-Command", "(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -eq '" + ip + "'} | Select-Object -First 1 -ExpandProperty PrefixLength)"])
    try:
        return str(ipaddress.ip_network(f"{ip}/{int(output.strip())}", strict=False))
    except (ValueError, TypeError):
        return str(ipaddress.ip_network(f"{ip}/24", strict=False)) if ip != "Unknown" else "Unknown"


def get_network() -> str:
    cidr = get_network_cidr()
    return cidr.split("/")[0].rsplit(".", 1)[0] + "." if cidr != "Unknown" else "Unknown"


def get_hostname() -> str:
    return socket.gethostname()


def get_wifi_name() -> str:
    output = _run(["netsh", "wlan", "show", "interfaces"])
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("SSID") and "BSSID" not in line and ":" in line:
            return line.split(":", 1)[1].strip() or "Unknown"
    return "Ethernet / Unknown"


def get_default_gateway() -> str:
    output = _run(["powershell", "-NoProfile", "-Command", "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop"])
    gateway = output.strip()
    if gateway and gateway != "0.0.0.0":
        return gateway
    # `route print` works without the CIM permissions that may be unavailable
    # in a restricted terminal.
    for line in _run(["route", "print", "-4", "0.0.0.0"]).splitlines():
        match = re.match(r"\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", line)
        if match:
            return match.group(1)
    return "Unknown"


def check_internet() -> bool:
    try:
        with socket.create_connection(("1.1.1.1", 53), timeout=2):
            return True
    except OSError:
        return False


def get_local_adapter() -> dict:
    ip = get_ip_address()
    output = _run(["getmac", "/FO", "CSV", "/NH"])
    mac_match = re.search(r'"([0-9A-Fa-f:-]{17})"', output)
    return {"hostname": get_hostname(), "ip": ip, "network": get_network_cidr(), "gateway": get_default_gateway(), "ssid": get_wifi_name(), "adapter_mac": normalize_mac(mac_match.group(1)) if mac_match else "Unknown", "dhcp_server": get_dhcp_server()}


def get_dhcp_server() -> str:
    """Return the DHCP server advertised to this Windows device, if any.

    Consumer routers don't expose their full lease table through a common,
    unauthenticated protocol.  Showing this address makes that limitation
    explicit while still identifying the service responsible for leases.
    """
    output = _run(["ipconfig", "/all"])
    match = re.search(r"DHCP Server[^:]*:\s*([0-9.]+)", output, re.IGNORECASE)
    return match.group(1) if match else "Not advertised / static IP"


def _dns_name(packet: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS name, including compression pointers, without a library."""
    labels, jumped, next_offset = [], False, offset
    visited = set()
    while offset < len(packet):
        length = packet[offset]
        if length == 0:
            offset += 1
            return ".".join(labels), (next_offset if jumped else offset)
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet): break
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if pointer in visited: break
            visited.add(pointer)
            if not jumped: next_offset = offset + 2
            jumped, offset = True, pointer
            continue
        offset += 1
        if offset + length > len(packet): break
        labels.append(packet[offset:offset + length].decode("utf-8", errors="ignore"))
        offset += length
    return ".".join(labels), (next_offset if jumped else offset)


def _mdns_hints(timeout: float = 1.6) -> dict[str, list[str]]:
    """Discover local mDNS responders (Apple, Chromecast, printers, HA, ...)."""
    hints: dict[str, list[str]] = {}
    # Standard DNS query: PTR _services._dns-sd._udp.local.
    query = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as connection:
            connection.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            connection.settimeout(0.2)
            connection.sendto(query, ("224.0.0.251", 5353))
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try: packet, sender = connection.recvfrom(9000)
                except socket.timeout: continue
                if len(packet) < 12: continue
                offset = 12
                for _ in range(int.from_bytes(packet[4:6], "big")):
                    _, offset = _dns_name(packet, offset)
                    offset += 4  # QTYPE + QCLASS
                records = int.from_bytes(packet[6:8], "big") + int.from_bytes(packet[8:10], "big") + int.from_bytes(packet[10:12], "big")
                for _ in range(records):
                    _, offset = _dns_name(packet, offset)
                    if offset + 10 > len(packet): break
                    record_type = int.from_bytes(packet[offset:offset + 2], "big")
                    data_len = int.from_bytes(packet[offset + 8:offset + 10], "big")
                    data_offset, offset = offset + 10, offset + 10 + data_len
                    if data_offset + data_len > len(packet): continue
                    if record_type == 1 and data_len == 4:  # IPv4 A record
                        ip = socket.inet_ntoa(packet[data_offset:data_offset + 4])
                        hints.setdefault(ip, []).append("mDNS responder")
                hints.setdefault(sender[0], []).append("mDNS responder")
    except OSError:
        pass
    return hints


def _ssdp_hints(timeout: float = 1.6) -> dict[str, list[str]]:
    """Ask for local UPnP/SSDP devices; responses include useful server names."""
    hints: dict[str, list[str]] = {}
    request = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as connection:
            connection.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            connection.settimeout(0.2)
            connection.sendto(request, ("239.255.255.250", 1900))
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try: data, sender = connection.recvfrom(4096)
                except socket.timeout: continue
                text = data.decode("utf-8", errors="ignore")
                headers = dict((key.strip().lower(), value.strip()) for key, _, value in (line.partition(":") for line in text.splitlines()[1:]) if key and value)
                name = headers.get("server") or headers.get("st") or headers.get("usn", "UPnP device")
                hints.setdefault(sender[0], []).append("SSDP: " + name[:96])
    except OSError:
        pass
    return hints


def get_local_discovery_hints() -> dict[str, list[str]]:
    """Collect multicast-only mDNS and SSDP clues in parallel."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        mdns, ssdp = pool.submit(_mdns_hints), pool.submit(_ssdp_hints)
        merged: dict[str, list[str]] = {}
        for result in (mdns.result(), ssdp.result()):
            for ip, values in result.items(): merged.setdefault(ip, []).extend(values)
        return merged


def get_arp_devices() -> dict[str, str]:
    result: dict[str, str] = {}
    for line in _run(["arp", "-a"]).splitlines():
        parts = line.split()
        if len(parts) >= 3 and normalize_mac(parts[1]) and parts[1].lower() != "ff-ff-ff-ff-ff-ff":
            try:
                ipaddress.ip_address(parts[0])
                result[parts[0]] = normalize_mac(parts[1]) or "Unknown"
            except ValueError:
                continue
    return result


def get_ping(ip: str, timeout_ms: int = 800) -> int | None:
    output = _run(["ping", "-n", "1", "-w", str(timeout_ms), ip], timeout=(timeout_ms / 1000) + 1)
    found = re.search(r"(?:time|tijd)[=<]?(\d+)\s*ms", output, re.IGNORECASE)
    return int(found.group(1)) if found else None


def _ping_host(ip: str) -> tuple[str, int | None]:
    return ip, get_ping(ip, 450)


def warm_arp_table(network: ipaddress.IPv4Network, own_ip: str, progress_callback=None) -> dict[str, int | None]:
    # Parallel, short ICMP probes populate Windows' ARP cache quickly. A device
    # may still be present when it blocks ICMP, so ARP entries are kept too.
    candidates = [str(host) for host in network.hosts() if str(host) != own_ip]
    result: dict[str, int | None] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=48) as pool:
        for index, (ip, ping) in enumerate(pool.map(_ping_host, candidates), start=1):
            if ping is not None:
                result[ip] = ping
            if progress_callback:
                progress_callback(index, len(candidates), "Discovering local addresses")
    return result


def get_device_name(ip: str) -> str:
    try:
        name = socket.gethostbyaddr(ip)[0]
        if name and name != ip:
            return name.rstrip(".")
    except (socket.herror, socket.gaierror, OSError):
        pass
    # Windows ping -a can expose a NetBIOS/LLMNR name even when reverse DNS does not.
    output = _run(["ping", "-a", "-n", "1", "-w", "350", ip], timeout=1.5)
    match = re.search(r"Pinging\s+([^\s\[]+)\s+\[" + re.escape(ip) + r"\]", output, re.IGNORECASE)
    return match.group(1) if match else "Unknown"


def get_netbios_name(ip: str) -> str | None:
    """Ask a Windows/SMB-capable LAN device for its NetBIOS workstation name."""
    output = _run(["nbtstat", "-A", ip], timeout=1.8)
    # A unique <00> entry is normally the user-facing computer/device name.
    match = re.search(r"^\s*([^\s<]+)\s+<00>\s+UNIQUE", output, re.MULTILINE | re.IGNORECASE)
    return match.group(1).strip() if match else None


def check_port(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=0.28):
            return True
    except OSError:
        return False


def scan_ports(ip: str) -> list[int]:
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        return [port for port, is_open in zip(COMMON_PORTS, pool.map(lambda port: check_port(ip, port), COMMON_PORTS)) if is_open]


def get_http_server(ip: str, ports: list[int]) -> str | None:
    port = 80 if 80 in ports else (443 if 443 in ports else None)
    if not port:
        return None
    try:
        with socket.create_connection((ip, port), timeout=0.6) as connection:
            # A short GET can reveal friendly router/printer/camera titles;
            # no credentials, forms, settings or follow-up requests are sent.
            connection.sendall(b"GET / HTTP/1.0\r\nHost: device\r\n\r\n")
            data = connection.recv(2048).decode("latin-1", errors="ignore")
            match = re.search(r"^Server:\s*(.+)$", data, re.MULTILINE | re.IGNORECASE)
            title = re.search(r"<title[^>]*>\s*(.*?)\s*</title>", data, re.IGNORECASE | re.DOTALL)
            if title:
                clean_title = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", title.group(1))).strip()
                if clean_title:
                    return clean_title[:96]
            return match.group(1).strip() if match else "Web interface"
    except OSError:
        return "Web interface"


def get_device_type(vendor: str, name: str, ports: list[int], role: str, clues: list[str] | None = None) -> str:
    text = f"{vendor} {name} {' '.join(clues or [])}".lower()
    if role == "Default Gateway": return "Router / Gateway"
    if 9100 in ports or "printer" in text: return "Printer"
    if "raspberry" in text: return "Mini computer"
    if "nintendo" in text or "xbox" in text or "playstation" in text: return "Gaming console"
    if "apple" in text: return "Apple device"
    if "samsung" in text or any(x in text for x in ("iphone", "android", "phone")): return "Phone / tablet"
    if any(x in text for x in ("dell", "lenovo", "hp", "asus", "microsoft")): return "Computer"
    if "tp-link" in text or "netgear" in text: return "Network device"
    if 554 in ports: return "Camera / media device"
    return "Unknown device"


def load_known_devices() -> dict:
    try:
        with open(KNOWN_DEVICES_FILE, "r", encoding="utf-8") as file:
            value = json.load(file)
            return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def get_known_device(mac: str | None) -> dict | None:
    normalized = normalize_mac(mac)
    for key, value in load_known_devices().items():
        if normalize_mac(key) == normalized and isinstance(value, dict):
            return value
    return None


def save_known_device(mac: str | None, name: str, device_type: str) -> bool:
    """Store a locally approved device; no data leaves this computer."""
    normalized = normalize_mac(mac)
    if not normalized:
        return False
    devices = load_known_devices()
    # Normalise an older duplicate key if it was written with another casing.
    for key in list(devices):
        if key != normalized and normalize_mac(key) == normalized:
            del devices[key]
    devices[normalized] = {"name": name.strip() or "Eigen apparaat", "type": device_type.strip() or "Bekend apparaat"}
    try:
        with open(KNOWN_DEVICES_FILE, "w", encoding="utf-8") as file:
            json.dump(devices, file, indent=2, ensure_ascii=False)
        return True
    except OSError:
        return False


def _enrich_device(item: tuple[str, str], pings: dict[str, int | None], gateway: str, discovery: dict[str, list[str]]) -> dict:
    ip, mac = item
    name = get_device_name(ip)
    if name == "Unknown":
        name = get_netbios_name(ip) or name
    vendor = get_vendor(mac)
    ports = scan_ports(ip)
    role = "Default Gateway" if ip == gateway else "Network device"
    known = get_known_device(mac)
    clues = discovery.get(ip, [])
    web_service = get_http_server(ip, ports)
    device_type = get_device_type(vendor, name, ports, role, clues + ([web_service] if web_service else []))
    if name == "Unknown" and clues:
        name = clues[0].replace("mDNS responder", "mDNS device")
    return {"ip": ip, "name": (known or {}).get("name", name), "mac": mac, "vendor": vendor, "type": (known or {}).get("type", device_type), "role": role, "status": "Known" if known else "Unknown", "ping": pings.get(ip) if ip in pings else get_ping(ip), "ports": ports, "web_service": web_service, "discovery": clues, "mac_privacy": "Randomized/private" if is_private_mac(mac) else "Factory MAC", "last_seen": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")}


def scan_network(progress_callback=None) -> tuple[list[dict], float]:
    started = time.perf_counter()
    own_ip, gateway, cidr = get_ip_address(), get_default_gateway(), get_network_cidr()
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return [], 0.0
    if progress_callback: progress_callback(0, 100, "Preparing local scan")
    pings = warm_arp_table(network, own_ip, lambda done, total, message: progress_callback(int(done * 70 / total), 100, message) if progress_callback else None)
    arp = get_arp_devices()
    if progress_callback: progress_callback(72, 100, "Listening for mDNS and SSDP devices")
    discovery = get_local_discovery_hints()
    ips = {ip for ip in arp if ipaddress.ip_address(ip) in network and ip != own_ip and ip != str(network.broadcast_address)}
    ips.update(pings)
    ips.update(ip for ip in discovery if ipaddress.ip_address(ip) in network and ip != own_ip)
    if gateway != "Unknown": ips.add(gateway)
    pairs = [(ip, arp.get(ip, "Unknown")) for ip in sorted(ips, key=lambda value: tuple(map(int, value.split("."))))]
    if progress_callback: progress_callback(78, 100, "Identifying discovered devices")
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        devices = []
        for index, device in enumerate(pool.map(lambda pair: _enrich_device(pair, pings, gateway, discovery), pairs), start=1):
            devices.append(device)
            if progress_callback:
                progress_callback(78 + int(index * 22 / max(len(pairs), 1)), 100, "Reading local device details")
    if progress_callback: progress_callback(100, 100, "Scan complete")
    return devices, round(time.perf_counter() - started, 2)


def assess_risk(device: dict) -> tuple[str, list[str]]:
    """Return a cautious exposure assessment, never a claim of compromise."""
    score, reasons = 0, []
    ports = set(device.get("ports", []))
    if device.get("status") == "Unknown":
        score += 1; reasons.append("staat niet in je lijst met bekende apparaten")
    for port, points, text in ((23, 4, "Telnet is bereikbaar"), (21, 2, "FTP is bereikbaar"), (3389, 2, "Extern bureaublad is bereikbaar"), (445, 1, "SMB-bestandsdeling is bereikbaar")):
        if port in ports:
            score += points; reasons.append(text)
    if not ports and device.get("status") == "Known":
        reasons.append("geen van de gecontroleerde diensten is bereikbaar")
    if score >= 4: return "REVIEW", reasons
    if score >= 2: return "NOTICE", reasons
    return "LOW", reasons or ["no concerning checked exposure"]


def update_device_history(devices: list[dict]) -> list[dict]:
    """Persist observations by MAC address and enrich this scan with history.

    'Last seen' means the last time this monitor observed the device, not an
    authoritative router connection timestamp. That distinction matters when a
    device is asleep or blocks network discovery.
    """
    try:
        with open(DEVICE_HISTORY_FILE, "r", encoding="utf-8") as file:
            history = json.load(file)
            if not isinstance(history, dict): history = {}
    except (OSError, json.JSONDecodeError):
        history = {}
    now = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
    present = set()
    for device in devices:
        key = normalize_mac(device.get("mac")) or "ip:" + device["ip"]
        present.add(key)
        previous = history.get(key, {})
        risk, reasons = assess_risk(device)
        device["first_seen"] = previous.get("first_seen", now)
        device["last_seen"] = now
        device["seen_count"] = int(previous.get("seen_count", 0)) + 1
        device["new_device"] = key not in history
        device["risk"] = risk
        device["risk_reasons"] = reasons
        history[key] = {"first_seen": device["first_seen"], "last_seen": now, "seen_count": device["seen_count"], "last_ip": device["ip"], "name": device["name"], "vendor": device["vendor"], "online": True}
    for key, saved in history.items():
        if key not in present:
            saved["online"] = False
    try:
        with open(DEVICE_HISTORY_FILE, "w", encoding="utf-8") as file:
            json.dump(history, file, indent=2, ensure_ascii=False)
    except OSError:
        pass
    return devices


def save_scan_snapshot(devices: list[dict]) -> None:
    snapshot = {"scanned_at": datetime.now(timezone.utc).isoformat(), "devices": devices}
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as file:
            json.dump(snapshot, file, indent=2, ensure_ascii=False)
    except OSError:
        pass
