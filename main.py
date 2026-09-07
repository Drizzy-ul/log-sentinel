#!/usr/bin/env python3
"""CLI Entrypoint for LogSentinel."""

import argparse
import sys
from logsentinel.config import Config
from logsentinel.service import SentinelService


def parse_arguments() -> Config:
    parser = argparse.ArgumentParser(
        description="LogSentinel: Automated real-time Nginx/Apache log monitor and firewall blocker.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-f", "--log-file",
        dest="log_file",
        default="access.log",
        help="Path to the Nginx or Apache access log file to monitor.",
    )
    parser.add_argument(
        "-b", "--backend",
        dest="firewall_backend",
        default="dry-run",
        choices=["iptables", "ufw", "nftables", "windows-netsh", "dry-run"],
        help="Firewall backend to execute OS commands.",
    )
    parser.add_argument(
        "-t", "--threshold",
        dest="attack_threshold",
        type=int,
        default=3,
        help="Number of attack infractions required within the time window to trigger a ban.",
    )
    parser.add_argument(
        "-w", "--window",
        dest="time_window",
        type=int,
        default=60,
        help="Sliding time window (in seconds) for rate-limiting offenses.",
    )
    parser.add_argument(
        "--no-dry-run",
        dest="dry_run",
        action="store_false",
        help="Disable dry-run mode and execute real OS firewall commands (Requires root/Admin privileges).",
    )
    parser.add_argument(
        "--from-beginning",
        dest="from_beginning",
        action="store_true",
        help="Process log file from the beginning rather than seeking to current end.",
    )
    parser.add_argument(
        "--whitelist",
        dest="whitelist",
        nargs="+",
        default=["127.0.0.1", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        help="Space-separated list of IP addresses or CIDR blocks to whitelist from bans.",
    )
    parser.add_argument(
        "--alert-log",
        dest="alert_log",
        default="alerts.log",
        help="Path to output JSON-lines alert log file.",
    )
    parser.add_argument(
        "--custom-block-cmd",
        dest="custom_block_cmd",
        default=None,
        help="Custom command template for blocking an IP (e.g. 'iptables -I INPUT -s {ip} -j DROP').",
    )

    args = parser.parse_args()

    return Config(
        log_file=args.log_file,
        firewall_backend=args.firewall_backend,
        attack_threshold=args.attack_threshold,
        time_window=args.time_window,
        whitelist=args.whitelist,
        dry_run=args.dry_run,
        from_beginning=args.from_beginning,
        alert_log=args.alert_log,
        custom_block_cmd=args.custom_block_cmd,
    )


def main():
    config = parse_arguments()
    service = SentinelService(config)
    service.start()


if __name__ == "__main__":
    main()
