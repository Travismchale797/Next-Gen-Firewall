#!/usr/bin/python3
import time
import re
import ipaddress
import subprocess
import traceback
from datetime import datetime

FASTLOG_PATH = "/var/log/suricata/fast.log"
BLOCK_LOG_PATH = "/var/log/blocks.log"

# Only act on these alerts (adjust if needed)
ALERT_KEYWORD = "CUSTOM"

# Never block these IPs (add yours here)
ALLOWLIST = {
    "127.0.0.1",
    "10.0.2.15",   # your VM IP from your screenshots
}

# fast.log line format typically includes: SRCIP:PORT -> DSTIP:PORT
IP_RE = re.compile(
    r'(\d{1,3}(?:\.\d{1,3}){3}):\d+\s*->\s*(\d{1,3}(?:\.\d{1,3}){3}):\d+'
)

def extract_src_ip(line: str):
    """Return source IP from a Suricata fast.log line, or None."""
    m = IP_RE.search(line)
    if not m:
        return None
    return m.group(1)

def is_private_or_local(ip: str) -> bool:
    """True if IP is private, loopback, link-local, multicast, etc."""
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
        )
    except ValueError:
        return True  # treat invalid as non-actionable

def iptables_has_drop(ip: str) -> bool:
    """Check whether we've already added a DROP rule for this source IP."""
    try:
        result = subprocess.run(
            ["iptables", "-t", "raw", "-S", "PREROUTING"],
            capture_output=True,
            text=True,
            check=True
        )
        # Look for the exact rule we add
        needle = f"-A PREROUTING -s {ip} -j DROP"
        return needle in result.stdout
    except Exception:
        # If iptables query fails, assume not present to avoid false positives
        return False

def log_block(ip: str, reason: str = ""):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = f"{timestamp} BLOCKED {ip}"
    if reason:
        msg += f" ({reason})"
    msg += "\n"

    try:
        with open(BLOCK_LOG_PATH, "a") as f:
            f.write(msg)
            f.flush()
    except Exception as e:
        print(f"[-] Failed writing {BLOCK_LOG_PATH}: {e}")

def block_ip(ip: str):
    """Add a raw PREROUTING DROP rule for source IP."""
    if ip in ALLOWLIST:
        return

    if is_private_or_local(ip):
        return

    if iptables_has_drop(ip):
        return

    # Add rule
    subprocess.run(
        ["iptables", "-t", "raw", "-A", "PREROUTING", "-s", ip, "-j", "DROP"],
        check=True
    )

    log_block(ip, reason="suricata fast.log CUSTOM alert")
    print(f"[+] Blocked {ip}")

def follow_fastlog():
    """
    Tail the fast.log like 'tail -f' and only process NEW lines.
    """
    print(f"[+] Monitoring {FASTLOG_PATH} for '{ALERT_KEYWORD}' alerts...")

    with open(FASTLOG_PATH, "r") as f:
        # Start at end so we don't re-process old history
        f.seek(0, 2)

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue

            if ALERT_KEYWORD not in line:
                continue

            ip = extract_src_ip(line)
            if not ip:
                # Uncomment if you want to debug unexpected formats:
                # print(f"[!] Could not parse IP from line: {line.strip()}")
                continue

            try:
                block_ip(ip)
            except subprocess.CalledProcessError as e:
                print(f"[-] iptables failed for {ip}: {e}")
            except Exception as e:
                print(f"[-] Error handling line: {e}")
                traceback.print_exc()

def main():
    while True:
        try:
            follow_fastlog()
        except FileNotFoundError:
            print(f"[-] {FASTLOG_PATH} not found yet. Waiting...")
            time.sleep(2)
        except Exception as e:
            print(f"[-] Crash in follow loop: {e}")
            traceback.print_exc()
            time.sleep(2)

if __name__ == "__main__":
    main()
