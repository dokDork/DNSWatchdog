#!/usr/bin/env python3
"""
pcap_analyzer.py — Analyze TCP and UDP connections from a PCAP/PCAPng file.

Usage:
    python3 pcap_analyzer.py <pcap_file> <source_ip>

Arguments:
    pcap_file   Path to the .pcap or .pcapng capture file (e.g. capture.pcapng)
    source_ip   The source IP address whose outbound traffic you want to analyze
                (e.g. 192.168.10.150)

Output:
    Two formatted tables:
      - TCP connections: destination hostname, IP, port, and whether the port
        was open or closed (RST received / no SYN-ACK).
      - UDP connections: destination hostname, IP, and port.

Hostname resolution strategy (in priority order):
    1. DNS A records captured in the pcap itself
    2. Temporal correlation: the DNS query made closest before a TCP/UDP
       connection is used as the hostname for that destination IP
    3. Reverse PTR lookup as a last-resort fallback

Requirements:
    pip install scapy
"""

import sys
import socket

try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS
except ImportError:
    print("Error: 'scapy' is not installed.  Run:  pip install scapy")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Usage / validation
# ---------------------------------------------------------------------------

def print_usage_and_exit() -> None:
    print()
    print("  PCAP Analyzer — inspect outbound TCP/UDP traffic from a given source IP")
    print()
    print("  Usage:")
    print("      python3 pcap_analyzer.py <pcap_file> <source_ip>")
    print()
    print("  Arguments:")
    print("      pcap_file   Path to a Wireshark capture file (.pcap or .pcapng)")
    print("      source_ip   IP address of the host whose traffic you want to analyse")
    print()
    print("  Examples:")
    print("      python3 pcap_analyzer.py capture.pcapng 192.168.10.150")
    print("      python3 pcap_analyzer.py traffic.pcap  10.0.0.5")
    print()
    sys.exit(1)


# ---------------------------------------------------------------------------
# DNS hostname extraction from pcap packets
# ---------------------------------------------------------------------------

def build_dns_maps(packets):
    """
    Parse all DNS packets and return:

      ip_map   : dict  ip_str -> hostname
                 Built from A records (type 1).  When a response contains both
                 a CNAME and an A record we store the *original query name*
                 (e.g. "graph.facebook.com") rather than the intermediate alias
                 ("star.c10r.facebook.com") so the output is human-readable.

      queries  : list of (timestamp_float, qname_str)
                 Every DNS question seen in the capture, in packet order.
                 Used for temporal correlation when an IP is not in ip_map.
    """
    ip_map  = {}
    queries = []

    for pkt in packets:
        if DNS not in pkt:
            continue

        dns = pkt[DNS]

        # Collect questions (qr == 0 means query)
        if dns.qr == 0 and dns.qd:
            qname = dns.qd.qname
            if isinstance(qname, bytes):
                qname = qname.decode(errors="replace")
            queries.append((float(pkt.time), qname.rstrip(".")))

        # Collect answers (qr == 1 means response)
        if dns.qr == 1 and dns.ancount > 0:
            # Determine the original query name from the question section
            origin = None
            if dns.qd:
                origin = dns.qd.qname
                if isinstance(origin, bytes):
                    origin = origin.decode(errors="replace")
                origin = origin.rstrip(".")

            an = dns.an
            while an and hasattr(an, "type"):
                if an.type == 1:  # A record
                    rdata  = getattr(an, "rdata",  None)
                    rrname = getattr(an, "rrname", b"")
                    if isinstance(rrname, bytes):
                        rrname = rrname.decode(errors="replace").rstrip(".")

                    if rdata:
                        # Prefer the original query name over the alias hostname
                        hostname = origin if origin else rrname
                        ip_map[rdata] = hostname

                # Advance through the linked answer chain
                an = an.payload if hasattr(an, "payload") else None
                if not hasattr(an, "type"):
                    break

    return ip_map, queries


def temporal_hostname(ip: str, first_syn_time: float, queries: list, window: float = 5.0):
    """
    Find the DNS query made *closest before* first_syn_time (within `window`
    seconds) and return its qname as the likely hostname for `ip`.

    This handles cases where the DNS A record was not captured (e.g. the
    answer arrived before the capture started) but the query itself was
    recorded.  A 5-second window is generous enough for normal name->connect
    sequences while avoiding false matches from unrelated earlier queries.
    """
    best_name  = None
    best_delta = float("inf")

    for ts, qname in queries:
        delta = first_syn_time - ts
        if 0 <= delta <= window and delta < best_delta:
            best_delta = delta
            best_name  = qname

    return best_name


def reverse_ptr(ip: str) -> str:
    """Reverse-DNS PTR lookup; returns the IP itself on failure."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return ip


# ---------------------------------------------------------------------------
# PCAP traffic analysis
# ---------------------------------------------------------------------------

def analyze(pcap_path: str, source_ip: str):
    """
    Parse the capture and return:
      tcp_results : dict  (dst_ip, dst_port) -> {"status": str, "first_syn": float}
      udp_results : dict  (dst_ip, dst_port) -> {"first_pkt": float}
      ip_map      : dict  ip -> hostname  (from DNS A records)
      queries     : list  (ts, qname)
    """
    print(f"\nLoading capture file: {pcap_path}")
    try:
        packets = rdpcap(pcap_path)
    except FileNotFoundError:
        print(f"Error: file not found — '{pcap_path}'")
        sys.exit(1)
    except Exception as exc:
        print(f"Error reading capture file: {exc}")
        sys.exit(1)

    print(f"Packets loaded     : {len(packets)}")
    print(f"Analysing source   : {source_ip}\n")

    # Build DNS maps before iterating traffic
    ip_map, queries = build_dns_maps(packets)

    # TCP state machine per (dst_ip, dst_port)
    tcp_results = {}   # key -> {"status": str, "first_syn": float}

    # UDP destinations
    udp_results = {}   # key -> {"first_pkt": float}

    SYN     = 0x02
    ACK     = 0x10
    RST     = 0x04
    SYN_ACK = SYN | ACK

    for pkt in packets:
        if IP not in pkt:
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst
        ts  = float(pkt.time)

        # ---- TCP --------------------------------------------------------
        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            flags = int(pkt[TCP].flags)

            # Outbound SYN from our source
            if src == source_ip:
                key = (dst, dport)
                if flags & SYN and not (flags & ACK):
                    if key not in tcp_results:
                        tcp_results[key] = {"status": "pending", "first_syn": ts}

            # Inbound reply to our source
            if dst == source_ip:
                key = (src, sport)
                if key in tcp_results:
                    if (flags & SYN_ACK) == SYN_ACK:
                        tcp_results[key]["status"] = "open"
                    elif flags & RST:
                        if tcp_results[key]["status"] != "open":
                            tcp_results[key]["status"] = "closed"

        # ---- UDP --------------------------------------------------------
        if UDP in pkt and src == source_ip:
            key = (dst, pkt[UDP].dport)
            if key not in udp_results:
                udp_results[key] = {"first_pkt": ts}

    # Treat any still-pending TCP entry as closed (filtered / timed-out)
    for key, info in tcp_results.items():
        if info["status"] == "pending":
            info["status"] = "closed"

    return tcp_results, udp_results, ip_map, queries


# ---------------------------------------------------------------------------
# Hostname resolution (combining all three strategies)
# ---------------------------------------------------------------------------

def resolve(ip: str, first_ts: float, ip_map: dict, queries: list) -> str:
    """
    Return the best hostname for `ip` using the three-tier strategy:
      1. DNS A record from the pcap
      2. Temporal correlation with DNS queries
      3. Reverse PTR fallback
    """
    if ip in ip_map:
        return ip_map[ip]

    temporal = temporal_hostname(ip, first_ts, queries)
    if temporal:
        return temporal

    ptr = reverse_ptr(ip)
    return ptr if ptr != ip else "(unresolved)"


# ---------------------------------------------------------------------------
# Table rendering
# ---------------------------------------------------------------------------

COL_SEP = "  "


def render_table(title: str, headers: list, rows: list) -> None:
    """Print a plain-text table with aligned columns."""
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    separator   = COL_SEP.join("-" * w for w in widths)
    header_line = COL_SEP.join(h.ljust(widths[i]) for i, h in enumerate(headers))
    bar = "=" * len(separator)

    print(bar)
    print(f" {title}")
    print(bar)
    print(header_line)
    print(separator)
    if rows:
        for row in rows:
            print(COL_SEP.join(str(cell).ljust(widths[i]) for i, cell in enumerate(row)))
    else:
        print("  (no entries found)")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) != 3:
        print_usage_and_exit()

    pcap_path = sys.argv[1]
    source_ip = sys.argv[2]

    # Basic IPv4 format sanity check
    parts = source_ip.split(".")
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        print(f"Error: '{source_ip}' does not look like a valid IPv4 address.")
        print_usage_and_exit()

    tcp_results, udp_results, ip_map, queries = analyze(pcap_path, source_ip)

    # ---- Resolve hostnames ----
    all_ips = {ip for ip, _ in tcp_results} | {ip for ip, _ in udp_results}
    print(f"Resolving {len(all_ips)} unique IP address(es) ...\n")

    hostname_cache = {}
    for ip in sorted(all_ips):
        # Find the earliest timestamp this IP was contacted
        first_ts = min(
            [info["first_syn"] for (dst, _), info in tcp_results.items() if dst == ip] +
            [info["first_pkt"] for (dst, _), info in udp_results.items() if dst == ip],
            default=0.0,
        )
        hostname_cache[ip] = resolve(ip, first_ts, ip_map, queries)

    # ---- Build TCP table rows ----
    tcp_rows = []
    for (dst_ip, dst_port), info in tcp_results.items():
        tcp_rows.append((
            hostname_cache.get(dst_ip, "(unresolved)"),
            dst_ip,
            dst_port,
            info["status"].upper(),
        ))
    # Sort: open first, then closed; within group by IP then port
    tcp_rows.sort(key=lambda r: (0 if r[3] == "OPEN" else 1, r[1], r[2]))

    # ---- Build UDP table rows ----
    udp_rows = []
    for (dst_ip, dst_port) in udp_results:
        udp_rows.append((
            hostname_cache.get(dst_ip, "(unresolved)"),
            dst_ip,
            dst_port,
        ))
    udp_rows.sort(key=lambda r: (r[1], r[2]))

    # ---- Print tables ----
    render_table(
        title=f"TCP CONNECTIONS  (source: {source_ip})",
        headers=["HOSTNAME", "DESTINATION IP", "PORT", "STATUS"],
        rows=tcp_rows,
    )

    render_table(
        title=f"UDP CONNECTIONS  (source: {source_ip})",
        headers=["HOSTNAME", "DESTINATION IP", "PORT"],
        rows=udp_rows,
    )

    print(f"Summary: {len(tcp_rows)} TCP destination(s), {len(udp_rows)} UDP destination(s).")
    print()


if __name__ == "__main__":
    main()
