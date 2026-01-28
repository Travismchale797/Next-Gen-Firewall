# Next-Gen Firewall Daemon (Suricata + Python + iptables) 

This project implements a lightweight “next-gen firewall” style daemon using Python. It monitors 
Suricata alerts in near real-time and automatically blocks malicious source IP addresses using iptables.

The goal of this project is to simulate a blue-team / SOC workflow:
- detection via IDS (Suricata)
- parsing and triage of alerts
- automated enforcement using firewall rules
- audit logging for validation and reporting tes

---

## Features

- Continuously monitors Suricata alert output (`/var/log/suricata/fast.log`)
- Detects custom alert signatures (e.g., alerts containing `CUSTOM`)
- Extracts source IP from Suricata fast.log entries
- Automatically blocks attacker traffic via:
  - `iptables -t raw PREROUTING -s <ip> -j DROP`
- Logs all blocks to `/var/log/blocks.log`
- Runs persistently as a background service using `systemd`

---

## How It Works 

Workflow:
1. Suricata generates an IDS alert
2. Python daemon reads `/var/log/suricata/fast.log`
3. Script detects a target keyword (example: `CUSTOM`)
4. Source IP is extracted from the alert line
5. Firewall drop rule is created with iptables
6. Action is written to `/var/log/blocks.log` for auditing

---

## Improvements for the future 
Future improvements for this project include adding whitelist support to prevent trusted IPs from ever being blocked, 
refining the blocking logic to focus only on external or suspicious IPs (instead of risking internal/local addresses), 
and reducing duplicate entries by tracking already-blocked IPs so the daemon does not repeatedly add the same DROP
rules and flood the logs with repeated block events.


