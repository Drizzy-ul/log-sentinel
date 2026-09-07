import os
import sys

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import time
import threading
from logsentinel.config import Config
from logsentinel.service import SentinelService
from scripts.log_generator import simulate_stream

log_path = os.path.join(BASE_DIR, "demo_access.log")
alert_path = os.path.join(BASE_DIR, "demo_alerts.log")

# Clean old demo files if present
for p in (log_path, alert_path):
    if os.path.exists(p):
        os.remove(p)

# Ensure log file exists before service starts
with open(log_path, "w", encoding="utf-8") as f:
    f.write("# LogSentinel Demo Log\n")

config = Config(
    log_file=log_path,
    firewall_backend="dry-run",
    attack_threshold=3,
    time_window=60,
    whitelist=["127.0.0.1", "::1", "10.0.0.0/8"],
    dry_run=True,
    from_beginning=False,
    alert_log=alert_path,
)

service = SentinelService(config)

# Run sentinel in background thread
sentinel_thread = threading.Thread(target=service.start, daemon=True)
sentinel_thread.start()

time.sleep(0.5)

print("\n=== STARTING LIVE TRAFFIC SIMULATION ===")
# Generate attacks and normal traffic
simulate_stream(log_path, delay=0.08)

time.sleep(1.0)
service.stop()

print("\n=== SIMULATION RESULTS ===")
print(f"Total banned IPs: {len(service.tracker.banned_ips)}")
for ip in sorted(service.tracker.banned_ips):
    print(f"  [BANNED] {ip}")

assert "198.51.100.25" in service.tracker.banned_ips, "Expected SQLi attacker 198.51.100.25 to be banned"
assert "203.0.113.88" in service.tracker.banned_ips, "Expected XSS attacker 203.0.113.88 to be banned"
assert "198.51.100.99" in service.tracker.banned_ips, "Expected Traversal attacker 198.51.100.99 to be banned"
assert "127.0.0.1" not in service.tracker.banned_ips, "Whitelisted 127.0.0.1 must NOT be banned"

print("\nSUCCESS: All security assertions passed! Demo completed cleanly.")
