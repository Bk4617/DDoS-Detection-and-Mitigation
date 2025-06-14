import pandas as pd
import numpy as np
import joblib
import xgboost as xgb
import ipaddress
import os
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# Load dataset (Fix mixed types & strip spaces)
df = pd.read_csv(r"C:\Users\ramakrishna\OneDrive\Desktop\DDOS\dataset1.csv", low_memory=False)
df.columns = df.columns.str.strip()  # Fix hidden spaces in column names

# Convert IP addresses to numeric values
def ip_to_int(ip):
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        return 0  # If invalid IP, set to 0

df["Source IP"] = df["Source IP"].astype(str).apply(ip_to_int)
df["Destination IP"] = df["Destination IP"].astype(str).apply(ip_to_int)

# Select all required features (Removed "Fwd Packet Length Min")
selected_features = [
    "Source IP", "Destination IP", "Destination Port", "Protocol",
    "Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Flow Duration"
]

# Ensure selected features exist in dataset
missing_features = [col for col in selected_features if col not in df.columns]
if missing_features:
    raise ValueError(f"Missing columns in dataset: {missing_features}")

X = df[selected_features]
y = df["Label"]  # Target column

# Print unique labels to verify correct mapping
print("Unique labels in dataset:", y.unique())

# Convert categorical labels to numeric
if y.dtype == 'object':
    y = y.astype('category')
    label_mapping = dict(enumerate(y.cat.categories))  # Store label names for confusion matrix
    y = y.cat.codes
else:
    label_mapping = dict(enumerate(sorted(y.unique())))  # Fallback

# Handle Inf and NaN issues properly
X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(X.mean())
X = X.clip(lower=-1e6, upper=1e6)

# Split data into train & test sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train XGBoost model
model = xgb.XGBClassifier(
    n_estimators=100, 
    learning_rate=0.1, 
    max_depth=6, 
    subsample=0.8, 
    colsample_bytree=0.8, 
    random_state=42
)
model.fit(X_train, y_train)

# Make predictions
y_pred = model.predict(X_test)

# Print accuracy & classification report
accuracy = accuracy_score(y_test, y_pred)

print("\nClassification Report:\n", classification_report(y_test, y_pred))

# Plot Confusion Matrix
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(10, 7))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=label_mapping.values(),
            yticklabels=label_mapping.values())
plt.xlabel("Predicted Label")
plt.ylabel("True Label")
plt.title("Confusion Matrix for DDoS Detection")
plt.tight_layout()
plt.show()

# Ensure the models directory exists
models_dir = os.path.join(os.path.dirname(__file__), "../models")
os.makedirs(models_dir, exist_ok=True)

# Save model
model_path = os.path.join(models_dir, "xgboost_ddos.pkl")
joblib.dump(model, model_path)

print(f"Model saved successfully at: {model_path}")
