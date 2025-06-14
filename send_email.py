import smtplib
import re
import ssl
import os
import pandas as pd
from email.message import EmailMessage

# Email Configuration
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
SENDER_EMAIL = "ramkii0106@gmail.com"
SENDER_PASSWORD = "xwvx bbsg zfmw ddta"
RECIPIENT_EMAIL = "rama01062003@gmail.com"

# Directory for DDoS traffic files
DDOS_FOLDER = r"C:\Users\ramakrishna\OneDrive\Desktop\DDOS\data\ddos_traffic"

# Get the latest DDoS file
def get_latest_ddos_file():
    ddos_files = [f for f in os.listdir(DDOS_FOLDER) if re.match(r"ddos_\d+\.csv$", f)]
    if not ddos_files:
        print("[✘] No DDoS traffic files found!")
        return None

    # Extract the number and sort
    def extract_number(filename):
        match = re.search(r"(\d+)", filename)
        return int(match.group(1)) if match else -1

    latest_file = sorted(ddos_files, key=extract_number)[-1]
    return os.path.join(DDOS_FOLDER, latest_file)

# Send Email Alert
def send_email_alert(ddos_file):
    msg = EmailMessage()
    msg["Subject"] = "DDoS Attack or High Network Traffic Detected!"
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECIPIENT_EMAIL
    msg.set_content(f"A DDoS attack has been detected. Attached: {os.path.basename(ddos_file)}")

    with open(ddos_file, "rb") as f:
        msg.add_attachment(f.read(), maintype="application", subtype="csv", filename=os.path.basename(ddos_file))

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)
        print(f"[✔] Email alert sent successfully! ({os.path.basename(ddos_file)})")
    except Exception as e:
        print(f"[✘] Failed to send email: {e}")

# Main
if __name__ == "__main__":
    latest_ddos_file = get_latest_ddos_file()
    if latest_ddos_file:
        send_email_alert(latest_ddos_file)
    else:
        print("[✘] No DDoS file found. No email sent.")

print("NOTIFICATION_COMPLETE")
