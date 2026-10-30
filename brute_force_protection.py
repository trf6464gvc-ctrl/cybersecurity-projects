import time
from datetime import datetime

# Store failed attempts
failed_attempts = {}
BLOCKED_USERS = {}
MAX_ATTEMPTS = 3
BLOCK_TIME = 60  # 60 seconds block

def is_blocked(username):
    if username in BLOCKED_USERS:
        if time.time() - BLOCKED_USERS[username] < BLOCK_TIME:
            return True
        else:
            del BLOCKED_USERS[username]
            failed_attempts[username] = 0
    return False

def login(username, password):
    correct_password = "Secure@123"
    
    if is_blocked(username):
        print(f"⛔ Account {username} is BLOCKED! Try after 1 minute")
        log_event(username, "BLOCKED_ATTEMPT")
        return False
    
    if password == correct_password:
        print(f"✅ Welcome {username}! Login Success")
        failed_attempts[username] = 0
        log_event(username, "SUCCESS")
        return True
    else:
        failed_attempts[username] = failed_attempts.get(username, 0) + 1
        remaining = MAX_ATTEMPTS - failed_attempts[username]
        
        print(f"❌ Wrong password! Attempts left: {remaining}")
        log_event(username, f"FAILED - Attempt {failed_attempts[username]}")
        
        if failed_attempts[username] >= MAX_ATTEMPTS:
            BLOCKED_USERS[username] = time.time()
            print(f"🚨 ALERT! {username} BLOCKED for {BLOCK_TIME} seconds!")
            log_event(username, "ACCOUNT_BLOCKED")
        
        return False

def log_event(username, event):
    with open("security_log.txt", "a") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] User: {username} - {event}\n")

# Test the system
if __name__ == "__main__":
    print("=== Cybersecurity Brute Force Protection Demo ===\n")
    
    # Simulate attacks
    login("admin", "1234")
    login("admin", "wrong")
    login("admin", "hack123")
    print("\n--- Now trying correct password but blocked ---\n")
    login("admin", "Secure@123")
    
    print("\nCheck security_log.txt for logs!")
