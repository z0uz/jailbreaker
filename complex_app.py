import sqlite3
import subprocess
import os

def handle_user_input(user_id, command):
    # SQL Injection Vulnerability
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    user = cursor.fetchone()

    # OS Command Injection Vulnerability
    if user:
        subprocess.run(f"ping -c 4 {command}", shell=True)

    # Hardcoded Credentials
    secret_key = "AKIA-FAKE-AWS-KEY-123456"
    
    # Path Traversal Vulnerability
    try:
        with open(f"/var/www/html/profiles/{user_id}.txt", "r") as f:
            profile_data = f.read()
    except Exception as e:
        profile_data = None

    return user, profile_data
