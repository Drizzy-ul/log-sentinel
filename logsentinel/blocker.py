"""Firewall interaction module executing OS commands via subprocess."""

import ipaddress
import logging
import subprocess
from dataclasses import dataclass
from typing import List, Optional

logger = logging.getLogger("LogSentinel.Blocker")


@dataclass
class BlockResult:
    ip: str
    action: str  # 'BLOCK' or 'UNBLOCK'
    backend: str
    command: List[str]
    success: bool
    returncode: int
    stdout: str
    stderr: str
    dry_run: bool


class FirewallBlocker:
    """Manages OS-level firewall blocks using iptables, ufw, nftables, or netsh."""

    def __init__(self, backend: str = "dry-run", dry_run: bool = True,
                 custom_block_cmd: Optional[str] = None,
                 custom_unblock_cmd: Optional[str] = None):
        self.backend = backend.lower()
        self.dry_run = dry_run
        self.custom_block_cmd = custom_block_cmd
        self.custom_unblock_cmd = custom_unblock_cmd

    def _validate_ip(self, ip_str: str):
        """Validate that the string is a genuine IPv4 or IPv6 address to prevent command injection."""
        return ipaddress.ip_address(ip_str.strip())

    def _build_command(self, ip_str: str, action: str = "BLOCK") -> List[str]:
        """Construct the precise command array for the target firewall backend."""
        # Use custom template if provided
        if action == "BLOCK" and self.custom_block_cmd:
            cmd_formatted = self.custom_block_cmd.format(ip=ip_str)
            return cmd_formatted.split()
        if action == "UNBLOCK" and self.custom_unblock_cmd:
            cmd_formatted = self.custom_unblock_cmd.format(ip=ip_str)
            return cmd_formatted.split()

        if self.backend == "iptables":
            flag = "-A" if action == "BLOCK" else "-D"
            return ["iptables", flag, "INPUT", "-s", ip_str, "-j", "DROP"]

        elif self.backend == "ufw":
            if action == "BLOCK":
                return ["ufw", "deny", "from", ip_str]
            else:
                return ["ufw", "delete", "deny", "from", ip_str]

        elif self.backend == "nftables":
            if action == "BLOCK":
                return ["nft", "add", "element", "inet", "filter", "blacklist", f"{{ {ip_str} }}"]
            else:
                return ["nft", "delete", "element", "inet", "filter", "blacklist", f"{{ {ip_str} }}"]

        elif self.backend in ("windows-netsh", "netsh"):
            rule_name = f"LogSentinel_Block_{ip_str}"
            if action == "BLOCK":
                return [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip_str}"
                ]
            else:
                return [
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_name}"
                ]

        elif self.backend == "dry-run":
            return ["echo", f"[DRY-RUN] {action} {ip_str}"]

        else:
            raise ValueError(f"Unsupported firewall backend: {self.backend}")

    def execute(self, ip_str: str, action: str = "BLOCK", reason: str = "") -> BlockResult:
        """Execute the firewall block/unblock command safely using subprocess.run."""
        # Validate IP string syntax strictly
        try:
            valid_ip = self._validate_ip(ip_str)
            sanitized_ip = str(valid_ip)
        except ValueError as err:
            logger.error(f"Cannot execute firewall rule for invalid IP address '{ip_str}': {err}")
            return BlockResult(
                ip=ip_str,
                action=action,
                backend=self.backend,
                command=[],
                success=False,
                returncode=-1,
                stdout="",
                stderr=f"Invalid IP address: {err}",
                dry_run=self.dry_run,
            )

        cmd = self._build_command(sanitized_ip, action=action)
        cmd_str = " ".join(cmd)

        if self.dry_run or self.backend == "dry-run":
            logger.warning(
                f"[SIMULATION] Dry-run enabled. Would execute: '{cmd_str}' (Reason: {reason})"
            )
            return BlockResult(
                ip=sanitized_ip,
                action=action,
                backend=self.backend,
                command=cmd,
                success=True,
                returncode=0,
                stdout="[DRY RUN SIMULATED SUCCESS]",
                stderr="",
                dry_run=True,
            )

        logger.info(f"Executing firewall command: {cmd_str}")
        try:
            # We explicitly do NOT use shell=True to prevent any possible shell injection
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            success = (proc.returncode == 0)
            if not success:
                logger.error(f"Firewall command failed with exit code {proc.returncode}: {proc.stderr.strip()}")
            else:
                logger.info(f"Successfully applied firewall rule for {sanitized_ip}")

            return BlockResult(
                ip=sanitized_ip,
                action=action,
                backend=self.backend,
                command=cmd,
                success=success,
                returncode=proc.returncode,
                stdout=proc.stdout.strip(),
                stderr=proc.stderr.strip(),
                dry_run=False,
            )
        except Exception as e:
            logger.exception(f"Exception during firewall command execution: {e}")
            return BlockResult(
                ip=sanitized_ip,
                action=action,
                backend=self.backend,
                command=cmd,
                success=False,
                returncode=-1,
                stdout="",
                stderr=str(e),
                dry_run=False,
            )

    def block_ip(self, ip_str: str, reason: str = "") -> BlockResult:
        """Block an IP address."""
        return self.execute(ip_str, action="BLOCK", reason=reason)

    def unblock_ip(self, ip_str: str, reason: str = "") -> BlockResult:
        """Unblock an IP address."""
        return self.execute(ip_str, action="UNBLOCK", reason=reason)
