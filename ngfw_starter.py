import datetime

# Example rule set
FIREWALL_RULES = [
    {"action": "ALLOW", "protocol": "TCP", "port": 80},
    {"action": "BLOCK", "protocol": "TCP", "port": 23},
    {"action": "ALLOW", "protocol": "UDP", "port": 53}
]

def log_event(action, protocol, port, result):
    with open("firewall_log.txt", "a") as log_file:
        log_file.write(f"{datetime.datetime.now()} | {action} {protocol}/{port} -> {result}\n")

def apply_rule(protocol, port):
    for rule in FIREWALL_RULES:
        if rule["protocol"] == protocol and rule["port"] == port:
            log_event(rule["action"], protocol, port, "MATCH")
            return rule["action"]
    log_event("BLOCK", protocol, port, "NO MATCH")
    return "BLOCK"
