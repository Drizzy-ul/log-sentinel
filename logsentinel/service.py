"""Central orchestrator connecting tailer, parser, detector, tracker, and blocker."""

import json
import logging
import os
import sys
import time
from datetime import datetime
from logsentinel.blocker import FirewallBlocker
from logsentinel.config import Config
from logsentinel.detector import AttackDetector
from logsentinel.parser import parse_log_line
from logsentinel.tailer import LogTailer
from logsentinel.tracker import IPTracker

# Enable ANSI colors on Windows 10/11 console
if sys.platform == "win32":
    os.system("")

# ANSI Color Codes
CLR_RESET = "\033[0m"
CLR_BOLD = "\033[1m"
CLR_RED = "\033[91m"
CLR_GREEN = "\033[92m"
CLR_YELLOW = "\033[93m"
CLR_CYAN = "\033[96m"
CLR_MAGENTA = "\033[95m"
CLR_GRAY = "\033[90m"

logger = logging.getLogger("LogSentinel")


class SentinelService:
    """Orchestrates the live log monitoring, threat detection, and active firewall blocking pipeline."""

    def __init__(self, config: Config):
        self.config = config
        self.tailer = LogTailer(
            filepath=config.log_file,
            from_beginning=config.from_beginning,
        )
        self.detector = AttackDetector()
        self.tracker = IPTracker(
            threshold=config.attack_threshold,
            time_window=config.time_window,
            whitelist=config.whitelist,
        )
        self.blocker = FirewallBlocker(
            backend=config.firewall_backend,
            dry_run=config.dry_run,
            custom_block_cmd=config.custom_block_cmd,
            custom_unblock_cmd=config.custom_unblock_cmd,
        )
        self.start_time = time.time()
        self.stats = {
            "lines_processed": 0,
            "threats_detected": 0,
            "bans_enacted": 0,
        }
        self._setup_logging()

    def _setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    def _write_alert(self, alert_data: dict):
        """Append an incident alert record to the alert log file."""
        if not self.config.alert_log:
            return
        try:
            with open(self.config.alert_log, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert_data) + "\n")
        except Exception as e:
            logger.error(f"Failed to write to alert log: {e}")

    def process_line(self, line: str):
        """Process a single raw log line through the security pipeline."""
        self.stats["lines_processed"] += 1
        entry = parse_log_line(line)
        if not entry:
            return

        threat = self.detector.analyze(entry)
        if not threat:
            return

        # An attack pattern was identified
        self.stats["threats_detected"] += 1
        ip = entry.ip
        timestamp_str = datetime.now().isoformat()

        # Severity color coding
        sev_color = CLR_RED if threat.severity in ("HIGH", "CRITICAL") else CLR_YELLOW
        print(
            f"{CLR_BOLD}{sev_color}[ALERT - {threat.category}]{CLR_RESET} "
            f"Rule: {CLR_CYAN}{threat.rule_name}{CLR_RESET} | "
            f"IP: {CLR_BOLD}{ip}{CLR_RESET} | "
            f"Severity: {sev_color}{threat.severity}{CLR_RESET} | "
            f"Target: {threat.matched_target} | "
            f"Payload: {CLR_MAGENTA}'{threat.matched_text}'{CLR_RESET} | "
            f"Path: {entry.request_uri}",
            flush=True
        )

        should_ban, offense_count = self.tracker.record_offense(ip, threat)

        alert_record = {
            "timestamp": timestamp_str,
            "ip": ip,
            "category": threat.category,
            "rule": threat.rule_name,
            "severity": threat.severity,
            "matched_text": threat.matched_text,
            "uri": entry.request_uri,
            "method": entry.method,
            "user_agent": entry.user_agent,
            "offense_count": offense_count,
            "threshold": self.config.attack_threshold,
            "banned": should_ban,
        }
        self._write_alert(alert_record)

        if should_ban:
            self.stats["bans_enacted"] += 1
            print(
                f"\n{CLR_BOLD}{CLR_RED}╔════════════════════════════════════════════════════════════════════════════════╗{CLR_RESET}\n"
                f"{CLR_BOLD}{CLR_RED}║ [ACTIVE FIREWALL MITIGATION TRIGGERED]                                         ║{CLR_RESET}\n"
                f"{CLR_BOLD}{CLR_RED}║ Offender IP:      {ip:<60} ║{CLR_RESET}\n"
                f"{CLR_BOLD}{CLR_RED}║ Offenses Count:   {str(offense_count) + ' infractions within ' + str(self.config.time_window) + 's':<60} ║{CLR_RESET}\n"
                f"{CLR_BOLD}{CLR_RED}║ Firewall Backend: {self.config.firewall_backend:<60} ║{CLR_RESET}\n"
                f"{CLR_BOLD}{CLR_RED}╚════════════════════════════════════════════════════════════════════════════════╝{CLR_RESET}\n",
                flush=True
            )
            result = self.blocker.block_ip(
                ip,
                reason=f"Exceeded threshold ({offense_count} attacks, last rule: {threat.rule_name})",
            )
            if result.success:
                print(
                    f"{CLR_BOLD}{CLR_GREEN}[SUCCESS]{CLR_RESET} Firewall rule applied for {CLR_BOLD}{ip}{CLR_RESET}: {' '.join(result.command)}\n",
                    flush=True
                )
            else:
                print(
                    f"{CLR_BOLD}{CLR_RED}[ERROR]{CLR_RESET} Failed to apply firewall rule for {ip}: {result.stderr}\n",
                    flush=True
                )

    def print_banner(self):
        mode_str = "DRY-RUN (Simulation Only)" if self.config.dry_run or self.config.firewall_backend == "dry-run" else "ACTIVE ENFORCEMENT"
        banner = f"""{CLR_BOLD}{CLR_CYAN}
  ██╗      ██████╗  ██████╗ ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
  ██║     ██╔═══██╗██╔════╝ ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
  ██║     ██║   ██║██║  ███╗███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
  ██║     ██║   ██║██║   ██║╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
  ███████╗╚██████╔╝╚██████╔╝███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
  ╚══════╝ ╚═════╝  ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝{CLR_RESET}
  {CLR_BOLD}Real-Time Nginx & Apache Access Log Intrusion Detection & Active Firewall Daemon{CLR_RESET}
  {CLR_GRAY}Version 1.0.0 | Author: Kelvin Amartey Winston | License: MIT{CLR_RESET}
{"=" * 86}
  {CLR_BOLD}Target Log:{CLR_RESET}        {self.config.log_file}
  {CLR_BOLD}Firewall Backend:{CLR_RESET}  {self.config.firewall_backend} [{CLR_YELLOW if 'DRY-RUN' in mode_str else CLR_GREEN}{mode_str}{CLR_RESET}]
  {CLR_BOLD}Threshold:{CLR_RESET}         {self.config.attack_threshold} infractions within {self.config.time_window}s window
  {CLR_BOLD}Read Mode:{CLR_RESET}         {'From Beginning' if self.config.from_beginning else 'Live Stream (Tail End)'}
  {CLR_BOLD}Whitelisted Subnets:{CLR_RESET}{', '.join(self.config.whitelist)}
{"=" * 86}
"""
        print(banner, flush=True)

    def print_summary(self):
        elapsed = time.time() - self.start_time
        print(f"\n{CLR_BOLD}{CLR_CYAN}{'=' * 30} LogSentinel Run Summary {'=' * 30}{CLR_RESET}")
        print(f"  Duration:            {elapsed:.2f} seconds")
        print(f"  Log Lines Monitored: {self.stats['lines_processed']}")
        print(f"  Attacks Detected:    {self.stats['threats_detected']}")
        print(f"  IPs Banned:          {len(self.tracker.banned_ips)}")
        if self.tracker.banned_ips:
            for ip in sorted(self.tracker.banned_ips):
                print(f"    - {CLR_RED}{ip}{CLR_RESET}")
        print(f"{CLR_BOLD}{CLR_CYAN}{'=' * 85}{CLR_RESET}\n")

    def start(self):
        """Start the real-time monitoring loop."""
        self.print_banner()
        try:
            for line in self.tailer.follow():
                self.process_line(line)
        except KeyboardInterrupt:
            print(f"\n{CLR_YELLOW}[INFO] Termination signal caught. Shutting down LogSentinel...{CLR_RESET}")
        finally:
            self.stop()
            self.print_summary()

    def stop(self):
        """Stop following logs."""
        self.tailer.stop()
