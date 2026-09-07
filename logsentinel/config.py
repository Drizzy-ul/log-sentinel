"""Configuration management for LogSentinel."""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Config:
    log_file: str = "access.log"
    firewall_backend: str = "dry-run"  # 'iptables', 'ufw', 'nftables', 'windows-netsh', 'dry-run'
    attack_threshold: int = 3          # Number of attack attempts before ban
    time_window: int = 60              # Sliding time window in seconds
    whitelist: List[str] = field(default_factory=lambda: [
        "127.0.0.1",
        "::1",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16"
    ])
    dry_run: bool = True               # Dry-run mode by default for safety
    from_beginning: bool = False       # Read from start of log instead of seeking to end
    alert_log: Optional[str] = "alerts.log"
    custom_block_cmd: Optional[str] = None
    custom_unblock_cmd: Optional[str] = None
