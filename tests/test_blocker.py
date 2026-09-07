"""Unit tests for firewall blocker and OS subprocess safety."""

import unittest
from logsentinel.blocker import FirewallBlocker


class TestFirewallBlocker(unittest.TestCase):
    def test_iptables_commands(self):
        blocker = FirewallBlocker(backend="iptables", dry_run=True)
        res = blocker.block_ip("198.51.100.7")
        self.assertTrue(res.success)
        self.assertEqual(res.command, ["iptables", "-A", "INPUT", "-s", "198.51.100.7", "-j", "DROP"])

        unblock_res = blocker.unblock_ip("198.51.100.7")
        self.assertTrue(unblock_res.success)
        self.assertEqual(unblock_res.command, ["iptables", "-D", "INPUT", "-s", "198.51.100.7", "-j", "DROP"])

    def test_ufw_commands(self):
        blocker = FirewallBlocker(backend="ufw", dry_run=True)
        res = blocker.block_ip("198.51.100.8")
        self.assertEqual(res.command, ["ufw", "deny", "from", "198.51.100.8"])

        unblock_res = blocker.unblock_ip("198.51.100.8")
        self.assertEqual(unblock_res.command, ["ufw", "delete", "deny", "from", "198.51.100.8"])

    def test_windows_netsh_commands(self):
        blocker = FirewallBlocker(backend="windows-netsh", dry_run=True)
        res = blocker.block_ip("198.51.100.9")
        self.assertIn("netsh", res.command)
        self.assertIn("action=block", res.command)
        self.assertIn("remoteip=198.51.100.9", res.command)

    def test_command_injection_prevention(self):
        blocker = FirewallBlocker(backend="iptables", dry_run=False)
        # Attempting shell injection payload in IP string
        malicious_ip = "198.51.100.1; rm -rf /"
        res = blocker.block_ip(malicious_ip)
        self.assertFalse(res.success)
        self.assertIn("Invalid IP address", res.stderr)
        self.assertEqual(res.command, [])
