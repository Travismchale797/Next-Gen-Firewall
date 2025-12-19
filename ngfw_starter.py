import datetime

# Enhanced rule set
FIREWALL_RULES = [
    {"action": "ALLOW", "protocol": "TCP", "port": 80},
    {"action": "BLOCK", "protocol": "TCP", "port": 23},
    {"action": "ALLOW", "protocol": "UDP", "port": 53},
    {"action": "BLOCK", "protocol": "TCP", "port_range": (1000, 2000)},
    {"action": "BLOCK", "protocol": "UDP", "port": 161, "src_ip": "192.168.1.100"}
]

def log_event(level, action, protocol, port, result):
    with open("firewall_log.txt", "a") as log_file:
        log_file.write(f"[{level}] {datetime.datetime.now()} | {action} {protocol}/{port} -> {result}\n")

def apply_rule(protocol, port, src_ip="0.0.0.0"):
    for rule in FIREWALL_RULES:
        if rule["protocol"] != protocol:
            continue
        
        # Match exact port
        if "port" in rule and rule["port"] == port:
            if "src_ip" in rule and rule["src_ip"] != src_ip:
                continue
            log_event("INFO", rule["action"], protocol, port, "MATCH")
            return rule["action"]

        # Match port range
        if "port_range" in rule:
            if rule["port_range"][0] <= port <= rule["port_range"][1]:
                log_event("ALERT", rule["action"], protocol, port, "PORT RANGE MATCH")
                return rule["action"]

    log_event("WARNING", "BLOCK", protocol, port, "NO MATCH")
    return "BLOCK"
 
