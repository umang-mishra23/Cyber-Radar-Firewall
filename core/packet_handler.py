# sentinelwall/core/packet_handler.py
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP
import sqlite3
import os
import time
from collections import defaultdict
from core.rule_engine import match_rule, add_rule_to_db

# Port scan tracker
scan_tracker = defaultdict(list)
SCAN_THRESHOLD = 10
SCAN_WINDOW = 5  # seconds

DB_PATH = os.path.join("data", "firewall.db")

def process_packet(packet):
    print("[*] Packet intercepted")



def is_port_scan(src_ip, dst_port):
    current_time = time.time()
    # Keep only recent entries
    scan_tracker[src_ip] = [
        (p, t) for (p, t) in scan_tracker[src_ip]
        if current_time - t < SCAN_WINDOW
    ]
    scan_tracker[src_ip].append((dst_port, current_time))
    unique_ports = set(p for (p, _) in scan_tracker[src_ip])
    return len(unique_ports) >= SCAN_THRESHOLD

def block_ip(ip):
    add_rule_to_db('block', ip)
    print(f"[+] {ip} auto-blocked and added to database.")

def process_packet(packet):
    scapy_packet = IP(packet.get_payload())

    if scapy_packet.haslayer(TCP):
        tcp_layer = scapy_packet[TCP]
        src_ip = scapy_packet.src
        dst_ip = scapy_packet.dst
        dst_port = tcp_layer.dport

        # Port scan detection logic
        if tcp_layer.flags == 'S':
            if is_port_scan(src_ip, dst_port):
                print(f"[!!! PORT SCAN DETECTED] {src_ip} scanning ports")
                block_ip(src_ip)
                packet.drop()
                return

        # Check firewall rules
        rule_action = match_rule(src_ip)
        if rule_action == 'block':
            print(f"[-] Packet from {src_ip} blocked")
            packet.drop()
        else:
            packet.accept()
    else:
        packet.accept()

def start_packet_filter():
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, process_packet)
    try:
        print("[*] Starting Cyber Radar packet filter...")
        nfqueue.run()
    except KeyboardInterrupt:
        print("[!] Stopping firewall...")
    finally:
        nfqueue.unbind()
