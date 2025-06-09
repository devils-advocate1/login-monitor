import win32evtlog
import re
import time
from collections import defaultdict
from datetime import datetime, timedelta
from config import *
import smtplib
from email.mime.text import MIMEText
import logging

failed_attempts = defaultdict(list)

# Setup logging
logging.basicConfig(filename='monitor.log', level=logging.INFO, format='%(asctime)s %(message)s')

def send_email_alert(ip, count):
    subject = f"[ALERT] Suspicious login attempts from {ip}"
    body = f"There have been {count} failed login attempts from {ip} within {TIME_WINDOW // 60} minutes."

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SENDER_EMAIL
    msg['To'] = RECEIVER_EMAIL

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)
        print(f"✅ Email alert sent for IP: {ip}")
        logging.info(f"Alert email sent for {ip} with {count} attempts")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")
        logging.error(f"Failed to send alert email for {ip}: {e}")

def extract_ip(description):
    ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
    match = re.search(ip_pattern, description)
    return match.group() if match else None

def monitor_failed_logins():
    server = 'localhost'
    log_type = 'Security'
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    last_record_number = 0

    print("🔍 Monitoring Windows Security Log for failed login attempts (Event ID 4625)...")

    while True:
        try:
            handle = win32evtlog.OpenEventLog(server, log_type)
            events = win32evtlog.ReadEventLog(handle, flags, 0)

            for event in events:
                if event.EventID == 4625 and event.RecordNumber > last_record_number:
                    ip = extract_ip(event.StringInserts[-1])
                    timestamp = event.TimeGenerated

                    if ip:
                        failed_attempts[ip].append(timestamp)
                        failed_attempts[ip] = [
                            t for t in failed_attempts[ip] if t > datetime.now() - timedelta(seconds=TIME_WINDOW)
                        ]
                        if len(failed_attempts[ip]) >= ALERT_THRESHOLD:
                            send_email_alert(ip, len(failed_attempts[ip]))
                            failed_attempts[ip] = []

                    last_record_number = event.RecordNumber
            win32evtlog.CloseEventLog(handle)
            time.sleep(10)
        except KeyboardInterrupt:
            print("🛑 Monitoring stopped.")
            break
        except Exception as e:
            print(f"❌ Error: {e}")
            logging.error(f"Monitoring error: {e}")
            time.sleep(10)

if __name__ == "__main__":
    monitor_failed_logins()
