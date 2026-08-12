#!/usr/bin/env python3
"""
sniffer.py — A simple educational network packet sniffer.

What it does
    Captures live network traffic on an interface and prints, for each
    packet: timestamp, source/destination IP, protocol, ports (if any),
    packet length, and a short preview of the payload.

However privileges are needed
    Reading raw packets off the wire requires the OS to give you access
    to a raw socket. That's an OS-level security control, so you must
    run this as root / Administrator, and only on networks/interfaces
    you own or have explicit permission to monitor.

How to run it
    sudo python3 sniffer.py                      # sniff default interface, all traffic
    sudo python3 sniffer.py -i eth0               # choose interface
    sudo python3 sniffer.py -f "tcp port 80"       # filter (see `man pcap-filter`)
    sudo python3 sniffer.py -c 50                  # stop after 50 packets
    sudo python3 sniffer.py --no-payload           # hide payload preview
    sudo python3 sniffer.py -w capture.pcap        # also save to a pcap file

Requirements
    pip install scapy
    (Linux/macOS: run with sudo. Windows: install Npcap and run as Admin.)
"""

import argparse
import datetime
import sys

try:
    from scapy.all import (
        sniff, wrpcap, conf,
        IP, IPv6, TCP, UDP, ICMP, ARP, Ether, Raw,
    )
except ImportError:
    print("scapy is not installed. Install it with:\n    pip install scapy")
    sys.exit(1)


# --------------------------------------------------------------------------
# Helpers to turn a packet into a human-readable summary.
# --------------------------------------------------------------------------

def protocol_name(pkt) -> str:
    """Work out the highest-level protocol we recognise in this packet."""
    if pkt.haslayer(ARP):
        return "ARP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(IP) or pkt.haslayer(IPv6):
        return "IP"
    if pkt.haslayer(Ether):
        return "Ethernet"
    return pkt.name if hasattr(pkt, "name") else "Unknown"


def get_addresses(pkt):
    """Return (src, dst) at the network layer, or (None, None) if not IP/ARP."""
    if pkt.haslayer(IP):
        return pkt[IP].src, pkt[IP].dst
    if pkt.haslayer(IPv6):
        return pkt[IPv6].src, pkt[IPv6].dst
    if pkt.haslayer(ARP):
        return pkt[ARP].psrc, pkt[ARP].pdst
    return None, None


def get_ports(pkt):
    """Return (sport, dport) for TCP/UDP, else (None, None)."""
    if pkt.haslayer(TCP):
        return pkt[TCP].sport, pkt[TCP].dport
    if pkt.haslayer(UDP):
        return pkt[UDP].sport, pkt[UDP].dport
    return None, None


def tcp_flags_str(pkt) -> str:
    """Human-readable TCP flags, e.g. 'SYN,ACK'."""
    if not pkt.haslayer(TCP):
        return ""
    flag_bits = pkt[TCP].flags
    return str(flag_bits)  # scapy already renders this like 'S', 'SA', 'PA', etc.


def payload_preview(pkt, max_bytes=64) -> str:
    """
    Show a short, safe preview of the raw payload bytes.
    Printable ASCII is shown as-is; everything else is shown as hex.
    This is not full decoding.
    """
    if not pkt.haslayer(Raw):
        return ""
    data = bytes(pkt[Raw].load)[:max_bytes]
    printable = "".join(
        chr(b) if 32 <= b < 127 else "." for b in data
    )
    return printable


def summarize(pkt, show_payload=True) -> str:
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    proto = protocol_name(pkt)
    src, dst = get_addresses(pkt)
    sport, dport = get_ports(pkt)
    length = len(pkt)

    parts = [f"[{ts}]", f"{proto:<8}", f"len={length:<5}"]

    if src and dst:
        addr = f"{src}"
        if sport is not None:
            addr += f":{sport}"
        addr += " -> " + dst
        if dport is not None:
            addr += f":{dport}"
        parts.append(addr)
    else:
        # Fall back to Ethernet addresses if we couldn't parse higher layers
        if pkt.haslayer(Ether):
            parts.append(f"{pkt[Ether].src} -> {pkt[Ether].dst}")

    if pkt.haslayer(TCP):
        parts.append(f"flags={tcp_flags_str(pkt)}")

    line = "  ".join(parts)

    if show_payload:
        preview = payload_preview(pkt)
        if preview:
            line += f"\n           payload: {preview!r}"

    return line


# --------------------------------------------------------------------------
# Main capture logic
# --------------------------------------------------------------------------

def make_handler(show_payload: bool, counters: dict):
    """Returns a per-packet callback that scapy's sniff() will invoke."""

    def handle(pkt):
        counters["total"] += 1
        proto = protocol_name(pkt)
        counters["by_proto"][proto] = counters["by_proto"].get(proto, 0) + 1
        print(summarize(pkt, show_payload=show_payload))

    return handle


def main():
    parser = argparse.ArgumentParser(
        description="Educational packet sniffer built with scapy.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-i", "--interface", default=None,
        help="Network interface to sniff on (default: scapy's default route interface)",
    )
    parser.add_argument(
        "-f", "--filter", default=None,
        help='BPF filter string, e.g. "tcp port 443" or "udp or icmp"',
    )
    parser.add_argument(
        "-c", "--count", type=int, default=0,
        help="Number of packets to capture (0 = capture until Ctrl+C)",
    )
    parser.add_argument(
        "-w", "--write", default=None,
        help="Also save captured packets to this pcap file (viewable in Wireshark)",
    )
    parser.add_argument(
        "--no-payload", action="store_true",
        help="Don't print the payload preview, just headers/summary",
    )
    args = parser.parse_args()

    if args.interface:
        conf.iface = args.interface

    counters = {"total": 0, "by_proto": {}}
    handler = make_handler(show_payload=not args.no_payload, counters=counters)

    print("=" * 70)
    print(" Network Sniffer — educational use only")
    print(f" Interface : {args.interface or conf.iface}")
    print(f" Filter    : {args.filter or '(none — capturing all traffic)'}")
    print(f" Count     : {'unlimited (Ctrl+C to stop)' if args.count == 0 else args.count}")
    print("=" * 70)

    try:
        packets = sniff(
            iface=args.interface,
            filter=args.filter,
            prn=handler,
            count=args.count if args.count > 0 else 0,
            store=bool(args.write),  # only keep packets in memory if we need to write them
        )
    except PermissionError:
        print("\nPermission denied. Packet capture needs elevated privileges.")
        print("Try: sudo python3 sniffer.py ...")
        sys.exit(1)
    except KeyboardInterrupt:
        pass

    print("\n" + "=" * 70)
    print(f" Capture stopped. Total packets: {counters['total']}")
    if counters["by_proto"]:
        print(" Breakdown by protocol:")
        for proto, n in sorted(counters["by_proto"].items(), key=lambda x: -x[1]):
            print(f"   {proto:<10} {n}")
    print("=" * 70)

    if args.write and 'packets' in dir() and packets is not None and len(packets) > 0:
        wrpcap(args.write, packets)
        print(f"Saved {len(packets)} packets to {args.write}")


if __name__ == "__main__":
    main()
