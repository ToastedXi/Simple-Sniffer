#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
import time
import argparse
from collections import defaultdict

# Track beaconing: regular outgoing connections from same src IP to same destination port
beacon_tracker = defaultdict(list)          # src_ip:dst_port -> list of timestamps
SYN_COUNT_THRESHOLD = 20                    # Alert if >20 SYN packets from one IP in ~1 minute
syn_counts = defaultdict(int)
last_reset = time.time()


def reset_syn_counts():
    """Reset SYN packet counters every 60 seconds"""
    global last_reset
    current = time.time()
    if current - last_reset > 60:
        syn_counts.clear()
        last_reset = current


def detect_beaconing(src_ip, dst_port):
    """Detect potential C2 beaconing based on regular timing (5-15 second intervals)"""
    key = f"{src_ip}:{dst_port}"
    timestamps = beacon_tracker[key]
    timestamps.append(time.time())

    # Keep only the most recent 10 timestamps
    if len(timestamps) > 10:
        timestamps.pop(0)

    if len(timestamps) >= 5:
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        avg_interval = sum(intervals) / len(intervals)
        if 4.5 < avg_interval < 15.5:
            print(f"[!] POTENTIAL BEACONING DETECTED: {src_ip} -> port {dst_port} (~{avg_interval:.1f}s intervals)")


def packet_callback(packet):
    global syn_counts
    reset_syn_counts()

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        print(f"[{time.strftime('%H:%M:%S')}] {src} > {dst}", end=" ")

        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = packet[TCP].flags
            print(f"TCP {sport} -> {dport} Flags: {flags}")

            # Detect potential port scan or SYN flood
            if 'S' in flags and not 'A' in flags:  # Pure SYN packet
                syn_counts[src] += 1
                if syn_counts[src] > SYN_COUNT_THRESHOLD:
                    print(f"[!!!] POTENTIAL PORT SCAN / SYN FLOOD from {src} ({syn_counts[src]} SYNs)")

            # Check for beaconing on TCP connections
            detect_beaconing(src, dport)

        elif UDP in packet and packet[UDP].dport == 53 and DNS in packet and packet[DNS].qr == 0:
            # Outgoing DNS query
            if DNSQR in packet:
                query = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                print(f"DNS Query: {query}")
                if len(query) > 60:
                    print(f"[!!!] SUSPICIOUS LONG DNS QUERY (possible tunneling): {query[:80]}...")

        else:
            print("Other protocol/layer")


def main():
    parser = argparse.ArgumentParser(description="Simple Packet Sniffer with Basic Alerts")
    parser.add_argument("-i", "--interface", default=None,
                        help="Network interface (e.g., eth0). Default: first available.")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Stop after N packets (0 = infinite)")
    args = parser.parse_args()

    print(f"[*] Starting sniffer on interface: {args.interface or 'default'}")
    print("[*] Alerts: Long DNS queries, SYN floods, potential beaconing")

    # Filter out SSH traffic by default to reduce noise on servers
    bpf_filter = "not port 22"

    sniff(iface=args.interface,
          prn=packet_callback,
          count=args.count,
          store=False,
          filter=bpf_filter)


if __name__ == "__main__":
    main()