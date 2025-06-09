# config.py

# Email Settings
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SENDER_EMAIL = 'sender@gmail.com'
SENDER_PASSWORD = 'password'  # Use App Password from Gmail/2 step verification
RECEIVER_EMAIL = 'reciver@gmail.com'

# Thresholds
ALERT_THRESHOLD = 3             # Max failed attempts
TIME_WINDOW = 600               # Time window in seconds (10 minutes)
