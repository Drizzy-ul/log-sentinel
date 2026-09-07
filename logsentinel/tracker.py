"""Sliding-window IP attack tracker and threshold enforcement."""

import ipaddress
import time
from collections import defaultdict, deque
from typing import Deque, Dict, List, Optional, Set, Tuple
from logsentinel.detector import ThreatMatch


class IPTracker:
    """Maintains a sliding time window of offenses per IP and determines ban eligibility."""

    def __init__(self, threshold: int = 3, time_window: int = 60, whitelist: Optional[List[str]] = None):
        self.threshold = threshold
        self.time_window = time_window
        self.whitelist_networks = []
        self._load_whitelist(whitelist or [])

        # Store timestamps of offenses per IP: ip -> deque([t1, t2, ...])
        self.offenses: Dict[str, Deque[float]] = defaultdict(deque)
        # Store banned IPs so duplicate ban commands are not repeatedly invoked
        self.banned_ips: Set[str] = set()

    def _load_whitelist(self, whitelist: List[str]):
        for item in whitelist:
            item = item.strip()
            if not item:
                continue
            try:
                net = ipaddress.ip_network(item, strict=False)
                self.whitelist_networks.append(net)
            except ValueError:
                pass

    def is_whitelisted(self, ip_str: str) -> bool:
        """Check if an IP address belongs to the configured whitelist."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return False

        for net in self.whitelist_networks:
            if ip_obj in net:
                return True
        return False

    def is_banned(self, ip_str: str) -> bool:
        """Check if an IP address is already tracked as banned."""
        return ip_str in self.banned_ips

    def record_offense(self, ip_str: str, threat: ThreatMatch, current_time: Optional[float] = None) -> Tuple[bool, int]:
        """
        Record an attack offense against an IP.

        Returns:
            Tuple[bool, int]: (should_ban, offense_count)
            should_ban is True ONLY on the exact transition crossing the threshold.
        """
        if self.is_whitelisted(ip_str):
            return False, 0

        if self.is_banned(ip_str):
            return False, len(self.offenses[ip_str])

        now = current_time if current_time is not None else time.time()
        window_start = now - self.time_window

        q = self.offenses[ip_str]

        # Prune entries older than the sliding window
        while q and q[0] < window_start:
            q.popleft()

        q.append(now)
        count = len(q)

        if count >= self.threshold:
            self.banned_ips.add(ip_str)
            return True, count

        return False, count

    def unban(self, ip_str: str):
        """Remove IP from the banned set."""
        if ip_str in self.banned_ips:
            self.banned_ips.remove(ip_str)
        if ip_str in self.offenses:
            self.offenses[ip_str].clear()
