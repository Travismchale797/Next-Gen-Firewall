#!/usr/bin/python3
import time
import subprocess
import traceback
from datetime import datetime

def is_blocked(ip):
    result = subprocess.run(["iptables", "-nL"], capture_output=True, text=True)
    return ip in result.stdout

def block_ip(ip):
    if not is_blocked(ip):
        subprocess.run(
            ["iptables", "-t", "raw", "-A", "PREROUTING", "-s", ip, "-j", "DROP"],
            check=True
        )
        log_block(ip)
        print(f"[+] Blocked {ip}")
    else:
        print(f"[=] Already blocked: {ip}")

def log_block(ip):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = f"{timestamp} BLOCKED {ip}\n"
    try:
        with open("/var/log/blocks.log", "a") as f:
            f.write(msg)
            f.flush()
    except Exception as e:
        print(f"[-] Failed writing /var/log/blocks.log: {e}")


def extract_ip(line):
    try:
        part = line.split("->")[0]
        ip_port = part.strip().split()[-1]
        return ip_port.split(":")[0]
    except Exception as e:
        print(f"[-] Failed to extract IP: {e}")
        return None

def is_external_ip(ip):
    return True

def monitor_fastlog():
    while True:
        try:
            with open("/var/log/suricata/fast.log", "r") as f:
                lines = f.read().splitlines()

            for line in lines:
                if "CUSTOM" in line:
                    ip = extract_ip(line)
                    if ip:
                       ip = ip.split(":")[0]
                       block_ip(ip)

        except Exception as e:
            print("[-] Error:", e)
            traceback.print_exc()

        time.sleep(5)

if __name__ == "__main__":
    try:
        monitor_fastlog()
    except Exception:
        traceback.print_exc()



