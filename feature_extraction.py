import os
import subprocess
import pandas as pd
import numpy as np
import ipaddress

# Define folders
extracted_data_folder = "C:/Users/ramakrishna/OneDrive/Desktop/DDOS/data/extracted_data"
os.makedirs(extracted_data_folder, exist_ok=True)

def get_next_filename():
    """Find the next available file name up to extracted_features100.csv"""
    existing_files = [f for f in os.listdir(extracted_data_folder) if f.startswith("extracted_features") and f.endswith(".csv")]
    existing_numbers = sorted([int(f.replace("extracted_features", "").replace(".csv", "")) for f in existing_files if f.replace("extracted_features", "").replace(".csv", "").isdigit()])
    
    if not existing_numbers:
        return os.path.join(extracted_data_folder, "extracted_features1.csv")
    
    if len(existing_numbers) < 100:
        return os.path.join(extracted_data_folder, f"extracted_features{existing_numbers[-1] + 1}.csv")
    
    # If 100 files exist, overwrite the oldest one
    return os.path.join(extracted_data_folder, f"extracted_features{existing_numbers[0]}.csv")

csv_file = get_next_filename()
latest_extracted_file = os.path.join(extracted_data_folder, "extracted_features.csv")  # Always overwrite this file

# Step 1: Capture Packets
INTERFACE = r"\Device\NPF_{B8AB59E1-CF66-43D2-9F95-6222ECA94273}"  # Change based on your system
print("Capturing 50,000 packets...")
capture_command = ["tshark", "-i", INTERFACE, "-c", "50000", "-w", "captured_packets.pcap"]
try:
    subprocess.run(capture_command, check=True)
    print("Packet capture complete.")
except subprocess.CalledProcessError as e:
    print(f"Error capturing packets: {e}")
    exit(1)

# Step 2: Extract Features
print("Extracting features from captured packets...")

tshark_fields = {
    "ip.src": "Source IP",
    "ip.dst": "Destination IP",
    "tcp.dstport": "Destination Port",
    "ip.proto": "Protocol",
    "frame.time_epoch": "Timestamp",
    "tcp.analysis.ack_rtt": "Total Fwd Packets",
    "tcp.analysis.retransmission": "Total Backward Packets",
    "tcp.len": "Total Length of Fwd Packets",
    "data.len": "Total Length of Bwd Packets"
}

extract_command = ["tshark", "-r", "captured_packets.pcap", "-T", "fields", "-E", "header=y", "-E", "separator=,", "-E", "quote=d"]
for tshark_field in tshark_fields.keys():
    extract_command += ["-e", tshark_field]

with open(csv_file, "w") as output_file:
    try:
        subprocess.run(extract_command, stdout=output_file, check=True)
        print(f"Features extracted and saved as {csv_file}")
    except subprocess.CalledProcessError as e:
        print(f"Error extracting features: {e}")
        exit(1)

# Step 3: Preprocess Data
df = pd.read_csv(csv_file)
df.rename(columns=tshark_fields, inplace=True)

# Convert IP addresses to numeric
def ip_to_int(ip):
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        return 0  # If invalid IP, set to 0

df["Source IP"] = df["Source IP"].astype(str).apply(ip_to_int)
df["Destination IP"] = df["Destination IP"].astype(str).apply(ip_to_int)

# Fill missing values
df.fillna(0, inplace=True)

# Convert timestamp to numeric and compute Flow Duration
df["Timestamp"] = pd.to_numeric(df["Timestamp"], errors="coerce")
df.sort_values(by=["Timestamp"], inplace=True)
df["Flow Duration"] = df["Timestamp"].diff().fillna(0) * 1e6  # Convert seconds to microseconds

# Ensure feature selection matches model
selected_features = [
    "Source IP", "Destination IP", "Destination Port", "Protocol",
    "Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Flow Duration"
]

# Ensure all features exist
missing_features = [col for col in selected_features if col not in df.columns]
if missing_features:
    print(f"Missing features detected: {missing_features}")
    raise ValueError(f"Still missing columns in dataset after computation: {missing_features}")

df = df[selected_features]
df[selected_features] = df[selected_features].apply(pd.to_numeric, errors='coerce')
df.fillna(df.mean(numeric_only=True), inplace=True)

# Save preprocessed data
df.to_csv(csv_file, index=False)
df.to_csv(latest_extracted_file, index=False)  # Always overwrite latest extracted file

print(f"Preprocessing complete. Cleaned data saved at:\n- {csv_file} (stored permanently)\n- {latest_extracted_file} (latest dataset)")
print("FEATURE_EXTRACTION_COMPLETE")
