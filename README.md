# CodeAlpha_NetworkSniffer

A lightweight Python network packet sniffer built with [Scapy](https://scapy.net/). Captures live traffic on a network interface and prints a readable, per-packet breakdown: timestamp, protocol, source/destination IP and port, TCP flags, and a short payload preview.
Built as a learning tool for understanding how data actually moves through a network and how the major protocols (Ethernet, IP, TCP/UDP, ARP, ICMP) layer on top of each other.

## Features

- Live packet capture on any interface, with optional filter support (`tcp port 443`, `udp or icmp`, etc.)
- Protocol detection across the stack: Ethernet → ARP/IP → TCP/UDP/ICMP
- Source/destination IP and port extraction, plus TCP flag decoding (SYN, ACK, FIN...)
- Payload preview (printable ASCII, non-printable bytes shown as dots)
- Optional `.pcap` export for follow-up analysis in Wireshark
- Per-protocol packet count summary when you stop capturing

## Requirements

- Python 3.9+
- [Npcap](https://npcap.com/) (Windows) or `libpcap` (Linux/macOS — usually preinstalled)
- Root/Administrator privileges (raw socket access is an OS-level restriction, not something this script can work around)

## Usage

```bash
sudo python3 sniffer.py                    # capture everything on the default interface
sudo python3 sniffer.py -i eth0             # choose a specific interface
sudo python3 sniffer.py -f "tcp port 80"     # only HTTP traffic
sudo python3 sniffer.py -c 50                # stop after 50 packets
sudo python3 sniffer.py --no-payload         # hide the payload preview
sudo python3 sniffer.py -w capture.pcap      # also save to a pcap file for Wireshark
```

### Example output

```
[14:22:01.183]  TCP       len=74     192.168.1.42:51422 -> 142.250.72.14:443   flags=S
[14:22:01.201]  TCP       len=74     142.250.72.14:443 -> 192.168.1.42:51422   flags=SA
[14:22:01.204]  UDP       len=82     192.168.1.42:56123 -> 8.8.8.8:53
           payload: '..........google.com.....'
```

## How it works

The script uses Scapy's `sniff()` to register a callback that fires on every captured packet. Each packet is a stack of layers (e.g. `Ether / IP / TCP / Raw`); the script walks that stack with `pkt.haslayer(...)` to identify the highest protocol present, pulls out addressing info from the appropriate layer, and prints a one-line summary. This mirrors how any real packet analyzer (tcpdump, Wireshark) works under the hood.

## License

MIT — see [LICENSE](LICENSE).
