import os
import pandas as pd
import numpy as np
import joblib

# Define folders
extracted_data_folder = r"C:\Users\ramakrishna\OneDrive\Desktop\DDOS\data\extracted_data"
predicted_data_folder = r"C:\Users\ramakrishna\OneDrive\Desktop\DDOS\data\predicted_data"
ddos_traffic_folder = r"C:\Users\ramakrishna\OneDrive\Desktop\DDOS\data\ddos_traffic"

# Load trained model
model_path = r"C:\Users\ramakrishna\OneDrive\Desktop\DDOS\models\xgboost_ddos.pkl"
model = joblib.load(model_path)

# Get latest extracted feature file
def get_latest_extracted_file():
    files = [f for f in os.listdir(extracted_data_folder) if f.startswith("extracted_features") and f.endswith(".csv")]
    files_sorted = sorted(files, key=lambda x: int(x.replace("extracted_features", "").replace(".csv", "")) if x.replace("extracted_features", "").replace(".csv", "").isdigit() else -1)

    if not files_sorted:
        raise FileNotFoundError("[✘] No extracted features file found!")

    latest_file = os.path.join(extracted_data_folder, files_sorted[-1])
    file_number = int(files_sorted[-1].replace("extracted_features", "").replace(".csv", ""))
    return latest_file, file_number

captured_data_path, extracted_file_number = get_latest_extracted_file()

# Load captured data
captured_df = pd.read_csv(captured_data_path)

# Ensure selected features match training data
selected_features = [
    "Source IP", "Destination IP", "Destination Port", "Protocol",
    "Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Flow Duration"
]

missing_features = [feat for feat in selected_features if feat not in captured_df.columns]
if missing_features:
    raise ValueError(f"[✘] Missing features in captured data: {missing_features}")

# Save original IPs for logging purposes
captured_df["Original Source IP"] = captured_df["Source IP"]
captured_df["Original Destination IP"] = captured_df["Destination IP"]

# Convert IPs to numeric format for ML model
captured_df["Source IP"] = captured_df["Source IP"].apply(lambda ip: hash(ip) % (10**8) if isinstance(ip, str) else ip)
captured_df["Destination IP"] = captured_df["Destination IP"].apply(lambda ip: hash(ip) % (10**8) if isinstance(ip, str) else ip)

# Predict
X_captured = captured_df[selected_features]
captured_df["Prediction_Prob"] = model.predict_proba(X_captured)[:, 1]

# Threshold for DDoS detection
threshold = 0.5  # Adjust this value
captured_df["Prediction"] = (captured_df["Prediction_Prob"] > threshold).astype(int)

# Save all predictions (both normal and DDoS)
prediction_file = os.path.join(predicted_data_folder, f"captured_predictions{extracted_file_number}.csv")
captured_df.to_csv(prediction_file, index=False)
print(f"[✓] All captured predictions saved: {prediction_file}")

# Filter only DDoS traffic
ddos_df = captured_df[captured_df["Prediction"] == 1]

# Reduce false positives: only high-activity IPs
ddos_ip_counts = ddos_df["Original Source IP"].value_counts()
ddos_ip_counts = ddos_ip_counts[ddos_ip_counts > 100].head(20)
ddos_df = ddos_df[ddos_df["Original Source IP"].isin(ddos_ip_counts.index)]

# Save DDoS traffic
if not ddos_df.empty:
    ddos_filename = os.path.join(ddos_traffic_folder, f"ddos_{extracted_file_number}.csv")
    ddos_df.to_csv(ddos_filename, index=False)
    print(f"[✓] DDoS traffic saved: {ddos_filename}")

print("DETECTION_COMPLETE")
