from core.packet_handler import start_packet_filter
from utils.iptables_setup import setup_iptables

def main():
    print("[*] Setting up iptables...")
    setup_iptables()

    print("[*] Starting Cyber Radar firewall engine...")
    try:
        start_packet_filter()
    except KeyboardInterrupt:
        print("\n[!] Cyber Radar Firewall stopped by user.")

if __name__ == "__main__":
    main()
