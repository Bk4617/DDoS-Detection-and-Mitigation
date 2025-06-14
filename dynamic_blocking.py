import pandas as pd
import os
import re
import subprocess
import socket
import struct


BLOCK_THRESHOLD = 10000  # Permanent block for extreme cases
TEMP_BLOCK_THRESHOLD = 5000  # Temporary block 
RATE_LIMIT_10_THRESHOLD = 4000  #(10 req/sec)
RATE_LIMIT_5_THRESHOLD = 2000  #  (5 req/sec)
RATE_LIMIT_2_THRESHOLD = 1000  #  (2 req/sec for bots)
BURST_THRESHOLD = 10000  # Instant block if 1000+ requests in 10 sec
REPEAT_OFFENSES_THRESHOLD = 3  # Long-term ban 

# File paths
PREDICTION_FOLDER = r"C:\Users\ramakrishna\OneDrive\Desktop\DDOS\data\predicted_data"

# Extract numeric part from filename
def extract_number(filename):
    match = re.search(r"(\d+)", filename)
    return int(match.group(1)) if match else -1

# Convert integer IP to dotted format if necessary
def int_to_ip(ip_val):
    try:
        return socket.inet_ntoa(struct.pack("!I", int(ip_val)))
    except:
        return str(ip_val)

# Get latest prediction file
prediction_files = [f for f in os.listdir(PREDICTION_FOLDER) if re.match(r"captured_predictions\d+\.csv$", f)]
if not prediction_files:
    raise FileNotFoundError(" No valid prediction files found!")

latest_file = sorted(prediction_files, key=extract_number)[-1]
file_number = extract_number(latest_file)  # Get the number from filename
latest_path = os.path.join(PREDICTION_FOLDER, latest_file)

print(f"Processing latest file: {latest_file}")

# Load prediction data
df = pd.read_csv(latest_path)
if "Source IP" not in df.columns or "Prediction" not in df.columns:
    raise ValueError("Missing required columns in data!")

# Separate DDoS traffic
ddos_df = df[df["Prediction"] == 1]

# Count occurrences of DDoS source IPs
ddos_ip_counts = ddos_df["Source IP"].value_counts().head(15)
repeat_offenders = {}

# Apply dynamic blocking & rate limiting
for ip, count in ddos_ip_counts.items():
    ip_str = int_to_ip(ip)  # Convert to dotted format if needed
    print(f" Processing IP: {ip_str} ")

    if count <= 1000:
        print(f" - High activity detected for IP: {ip_str}")
    elif count > 1000 and count <= 2000:
        print(f" - Rate limiting (10 req/sec) for IP: {ip_str}")
        subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name=RateLimit10", 
                        "dir=in", "action=block", "remoteip=" + ip_str], check=False)
    elif count > 2000 and count <= 5000:
        print(f" - Rate limiting (5 req/sec) for IP: {ip_str}")
        subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name=RateLimit5", 
                        "dir=in", "action=block", "remoteip=" + ip_str], check=False)
    elif count > 5000 and count <= 10000:
        print(f" - Temporary block (10 min) applied to IP: {ip_str}")
        subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name=TempBlock", 
                        "dir=in", "action=block", "remoteip=" + ip_str], check=False)
    elif count > 10000:
        print(f" - Permanent block applied to IP: {ip_str}")
        subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name=PermanentBlock", 
                        "dir=in", "action=block", "remoteip=" + ip_str], check=False)

    if count > BURST_THRESHOLD:
        print(f" - Instant Block: {ip_str} exceeded {BURST_THRESHOLD} requests in 10 sec")
        subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name=InstantBlock", 
                        "dir=in", "action=block", "remoteip=" + ip_str], check=False)

    repeat_offenders[ip_str] = repeat_offenders.get(ip_str, 0) + 1
    if repeat_offenders[ip_str] >= REPEAT_OFFENSES_THRESHOLD:
        print(f" - Long-term IP Ban: {ip_str} has been blocked {REPEAT_OFFENSES_THRESHOLD} times")
        subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name=LongTermBlock", 
                        "dir=in", "action=block", "remoteip=" + ip_str], check=False)

print("Rate limitig completed successfully!")
print("BLOCKING_COMPLETE")
