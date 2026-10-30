def detect_scan(logs):
    ip_ports = {}
    for log in logs:
        ip = log['ip']
        port = log['port']
        if ip not in ip_ports:
            ip_ports[ip] = set()
        ip_ports[ip].add(port)
        if len(ip_ports[ip]) > 10:
            return f"ALERT! Port Scan from {ip} - {len(ip_ports[ip])} ports"
    return "Traffic Normal"

# test
test_logs = [{'ip': '10.0.0.5', 'port': i} for i in range(15)]
print(detect_scan(test_logs))