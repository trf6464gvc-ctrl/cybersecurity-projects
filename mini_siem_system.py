from datetime import datetime, timedelta
from collections import defaultdict
import json

class MiniSIEM:
    def __init__(self):
        self.logs = []
        self.alerts = []
        self.ip_attempts = defaultdict(list)
    
    def add_log(self, username, ip_address, status, country="EG"):
        timestamp = datetime.now()
        log_entry = {
            "time": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "timestamp_obj": timestamp,
            "user": username,
            "ip": ip_address,
            "status": status,
            "country": country
        }
        self.logs.append(log_entry)
        self.ip_attempts[ip_address].append(log_entry)
        
        print(f"[{log_entry['time']}] {username} from {ip_address} - {status}")
        
        # Run detection rules
        self.detect_brute_force(ip_address)
        self.detect_impossible_travel(username, ip_address, country, timestamp)
        self.detect_off_hours_login(timestamp, username)
    
    def detect_brute_force(self, ip):
        """Rule 1: More than 5 failed attempts in 2 minutes = Attack"""
        recent_attempts = [
            log for log in self.ip_attempts[ip]
            if log['status'] == 'FAILED' and 
            datetime.now() - log['timestamp_obj'] < timedelta(minutes=2)
        ]
        
        if len(recent_attempts) >= 5:
            alert = f"🚨 CRITICAL: Brute Force Attack from IP {ip} - {len(recent_attempts)} failed attempts!"
            if alert not in self.alerts[-3:]: # Avoid spam
                self.alerts.append(alert)
                print(alert)
                self.write_alert(alert)
    
    def detect_impossible_travel(self, user, ip, country, timestamp):
        """Rule 2: Login from Egypt then USA in 10 mins = Impossible"""
        user_logs = [l for l in self.logs if l['user'] == user][-2:]
        if len(user_logs) >= 2:
            last_country = user_logs[-2]['country']
            time_diff = timestamp - user_logs[-2]['timestamp_obj']
            if last_country != country and time_diff < timedelta(minutes=10):
                alert = f"⚠️ HIGH: Impossible Travel for {user} - {last_country} -> {country} in {time_diff.seconds//60} mins!"
                self.alerts.append(alert)
                print(alert)
                self.write_alert(alert)
    
    def detect_off_hours_login(self, timestamp, user):
        """Rule 3: Login at 3 AM is suspicious"""
        if timestamp.hour >= 2 and timestamp.hour <= 5:
            alert = f"🔍 MEDIUM: Off-hours login - {user} logged in at {timestamp.hour}:00 AM"
            self.alerts.append(alert)
            print(alert)
            self.write_alert(alert)
    
    def write_alert(self, alert_msg):
        with open("siem_alerts.txt", "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now()}] {alert_msg}\n")
    
    def generate_report(self):
        print("\n" + "="*50)
        print("📊 SIEM DAILY SECURITY REPORT")
        print("="*50)
        print(f"Total Logs Analyzed: {len(self.logs)}")
        print(f"Total Alerts Generated: {len(self.alerts)}")
        print("\nTop Attacker IPs:")
        for ip, attempts in sorted(self.ip_attempts.items(), key=lambda x: len(x[1]), reverse=True)[:3]:
            failed = len([a for a in attempts if a['status'] == 'FAILED'])
            print(f"  - {ip}: {failed} failed logins")
        print("\nAll Alerts:")
        for a in self.alerts:
            print(f"  {a}")

# --- Demo Simulation of SOC Day ---
if __name__ == "__main__":
    siem = MiniSIEM()
    print("🛡️ Mini SIEM Started - Monitoring Live...\n")
    
    # Normal login
    siem.add_log("admin", "192.168.1.10", "SUCCESS", "EG")
    # Attacker trying
    for i in range(6):
        siem.add_log("admin", "45.33.22.11", "FAILED", "RU")
    
    # Impossible travel
    siem.add_log("ahmed", "197.36.40.1", "SUCCESS", "EG")
    siem.add_log("ahmed", "8.8.8.8", "SUCCESS", "US")
