"""Netwerk-monitor: privacyvriendelijke lokale apparaatdetectie."""
from __future__ import annotations

import argparse
import json
from datetime import datetime

import netwerk_info
import systeem_info

RESET, RED, GREEN, YELLOW, CYAN, BLUE, WHITE, GRAY = "\033[0m", "\033[91m", "\033[92m", "\033[93m", "\033[96m", "\033[94m", "\033[97m", "\033[90m"

def c(text, color): return color + str(text) + RESET
def status(value): return c(value, {"OK": GREEN, "WARNING": YELLOW, "INFO": CYAN}.get(value, WHITE))
def line(): print(c("=" * 72, BLUE))

def show_progress(done, total, message):
    percent = int(done * 100 / max(total, 1))
    previous = getattr(show_progress, "last_percent", -1)
    if percent == previous and percent not in (0, 100): return
    show_progress.last_percent = percent
    width, filled = 28, int(percent * 28 / 100)
    bar = "#" * filled + "." * (width - filled)
    print(f"\r{CYAN}ZOEKEN    [{bar}] {percent:3}%{RESET}  {message:<32}", end="", flush=True)

def print_device(device):
    risk_color = {"LOW": GREEN, "NOTICE": YELLOW, "REVIEW": RED}.get(device["risk"], WHITE)
    risk_name = {"LOW": "LAAG", "NOTICE": "LET OP", "REVIEW": "CONTROLEREN"}.get(device["risk"], device["risk"])
    state = "Bekend" if device["status"] == "Known" else "Onbekend"
    print(c("\n+-- APPARAAT", WHITE), c(state, GREEN if device["status"] == "Known" else YELLOW), c(risk_name, risk_color))
    print(f"|  {c('Naam', GRAY):22} {device['name']}")
    ping = str(device['ping']) + ' ms' if device['ping'] is not None else 'Geen ICMP-antwoord'
    print(f"|  {c('IP-adres', GRAY):22} {device['ip']}   {c('Ping', GRAY)} {ping}")
    print(f"|  {c('MAC-adres', GRAY):22} {device['mac']}  ({device['mac_privacy']})")
    print(f"|  {c('Fabrikant', GRAY):22} {device['vendor']}")
    print(f"|  {c('Type / rol', GRAY):22} {device['type']} / {device['role']}")
    services = ", ".join(f"{port}/{netwerk_info.PORT_NAMES.get(port, 'TCP')} [{status(netwerk_info.PORT_SECURITY.get(port, 'INFO'))}]" for port in device['ports']) or "Geen gevonden"
    print(f"|  {c('Diensten', GRAY):22} {services}")
    if device.get("web_service"): print(f"|  {c('Webinterface', GRAY):22} {device['web_service']}")
    if device.get("discovery"): print(f"|  {c('Lokale detectie', GRAY):22} {'; '.join(dict.fromkeys(device['discovery']))}")
    print(f"|  {c('Risicogrond', GRAY):22} {'; '.join(device['risk_reasons'])}")
    print(f"|  {c('Eerst / laatst gezien', GRAY):22} {device['first_seen']} / {device['last_seen']}")
    print(f"`-- {c('Aantal waarnemingen', GRAY):22} {device['seen_count']}{'  (NIEUW)' if device['new_device'] else ''}")

def mark_known_devices(devices):
    """Simple terminal checkbox flow for locally approving devices."""
    unknown = [device for device in devices if device["status"] == "Unknown"]
    if not unknown:
        return
    print(f"\n{c('ONBEKENDE APPARATEN', CYAN)}")
    print("Markeer apparaten die je herkent. Ze worden alleen lokaal opgeslagen.")
    for index, device in enumerate(unknown, start=1):
        warning = "  (MAC is gerandomiseerd; herkenning kan wijzigen)" if "Randomized" in device["mac_privacy"] else ""
        print(f"  [ ] {index}. {device['ip']:<15} {device['name']:<28} {device['type']}{warning}")
    try:
        choice = input("Nummers om als bekend te markeren (bv. 1,3; Enter = overslaan): ").strip()
    except (EOFError, KeyboardInterrupt):
        print(); return
    if not choice:
        return
    selected = set()
    for part in choice.split(","):
        try:
            number = int(part.strip())
            if 1 <= number <= len(unknown): selected.add(number)
        except ValueError:
            continue
    for number in sorted(selected):
        device = unknown[number - 1]
        try:
            name = input(f"  Naam voor {device['ip']} [{device['name']}]: ").strip() or device["name"]
        except (EOFError, KeyboardInterrupt):
            print(); break
        if netwerk_info.save_known_device(device["mac"], name, device["type"]):
            device["status"] = "Known"
            print(c(f"  [x] {name} opgeslagen als bekend apparaat.", GREEN))
        else:
            print(c("  Kon dit MAC-adres niet opslaan.", RED))

def main():
    parser = argparse.ArgumentParser(description="Privacyvriendelijke lokale apparaatdetectie")
    parser.add_argument("--json", action="store_true", help="toon het volledige rapport als JSON")
    args = parser.parse_args()
    adapter = netwerk_info.get_local_adapter()
    if not args.json:
        show_progress.last_percent = -1
        print(c("\nVeilige lokale detectie starten...", CYAN))
    devices, scan_time = netwerk_info.scan_network(None if args.json else show_progress)
    if not args.json: print()
    devices = netwerk_info.update_device_history(devices)
    netwerk_info.save_scan_snapshot(devices)
    report = {"scan_time": datetime.now().astimezone().isoformat(), "adapter": adapter, "internet": netwerk_info.check_internet(), "devices": devices, "duration_seconds": scan_time}
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False)); return
    print(); line(); print(c("  NETWERK-MONITOR 3.0  |  LOKAAL APPARATENOVERZICHT", CYAN)); line()
    print(f"\n{c('NETWERKADAPTER', CYAN)}  {adapter['hostname']}  |  {adapter['ssid']}")
    print(f"  Netwerk       {adapter['network']}\n  Dit apparaat  {adapter['ip']}  |  MAC {adapter['adapter_mac']}\n  Gateway       {adapter['gateway']}\n  DHCP-server   {adapter['dhcp_server']}\n  Internet      {c('Online', GREEN) if report['internet'] else c('Offline', RED)}")
    print(f"\n{c('DETECTIE KLAAR', CYAN)}  {len(devices)} apparaat/apparaten | {scan_time}s | momentopname in scan_history.json")
    warnings = sum(1 for device in devices if device['risk'] in ('NOTICE', 'REVIEW'))
    print(f"  Bereikbare diensten: {sum(len(device['ports']) for device in devices)} | Apparaten om te controleren: {warnings}")
    for device in devices: print_device(device)
    mark_known_devices(devices)
    system, release = systeem_info.get_system_info()
    print(f"\n{c('KORTE UITLEG', CYAN)}\n  IP-adres         Lokaal adres van het apparaat op dit netwerk.\n  MAC-adres        Hardware-adres van de netwerkkaart; 'Randomized' beschermt privacy.\n  Lokale detectie  Naam/service-aanwijzingen op je LAN via mDNS of SSDP/UPnP.\n  Diensten         Bereikbare veelgebruikte netwerkdiensten; geen volledige securityscan.\n  Laatst gezien    Laatste moment waarop deze monitor het apparaat zag.\n  Risico           Aanwijzing voor blootstelling; CONTROLEREN is geen bewijs van een hack.\n\n{c('SYSTEEM', CYAN)}  {system} {release}\n{GRAY}Vroege bèta.{RESET}")

if __name__ == "__main__": main()
