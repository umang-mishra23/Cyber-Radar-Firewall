import os

def setup_iptables():
    print("[*] Flushing old iptables rules...")
    os.system("sudo iptables -F")

    print("[*] Redirecting INPUT, OUTPUT, FORWARD to NetfilterQueue...")
    os.system("sudo iptables -I FORWARD -j NFQUEUE --queue-num 0")
    os.system("sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0")
    os.system("sudo iptables -I INPUT -j NFQUEUE --queue-num 0")
