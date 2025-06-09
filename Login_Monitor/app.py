# app.py
from flask import Flask, render_template, request
from config import *
import time
import smtplib
import logging
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

app = Flask(__name__)
FAILED_LOGINS = {}

# Setup logging
logging.basicConfig(filename='login_monitor.log', level=logging.INFO, format='%(asctime)s %(message)s')

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    ip = request.remote_addr
    username = request.form['username']
    password = request.form['password']

    if username == 'admin' and password == 'admin123':
        FAILED_LOGINS.pop(ip, None)
        return "✅ Login successful!"
    else:
        FAILED_LOGINS.setdefault(ip, []).append(time.time())
        FAILED_LOGINS[ip] = [t for t in FAILED_LOGINS[ip] if t > time.time() - TIME_WINDOW]

        logging.info(f"Failed login attempt from {ip}")

        if len(FAILED_LOGINS[ip]) >= ALERT_THRESHOLD:
            send_email_alert(ip, len(FAILED_LOGINS[ip]))
            FAILED_LOGINS[ip] = []

        return render_template('login.html', error="❌ Invalid credentials!")

def send_email_alert(ip, count):
    subject = f"[ALERT] {count} Failed Login Attempts from {ip}"
    body = f"<p>There have been <b>{count}</b> failed login attempts from IP: <b>{ip}</b> within {TIME_WINDOW // 60} minutes.</p>"

    msg = MIMEMultipart()
    msg['Subject'] = subject
    msg['From'] = SENDER_EMAIL
    msg['To'] = RECEIVER_EMAIL
    msg.attach(MIMEText(body, 'html'))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)
        print(f"✅ Email alert sent for IP: {ip}")
        logging.info(f"Email alert sent for {ip} with {count} attempts")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")
        logging.error(f"Failed to send email alert for {ip}: {e}")

if __name__ == '__main__':
    app.run(debug=True, port=5001)
