"""Unit tests for the IP offense tracker and threshold management."""

import unittest
from logsentinel.detector import ThreatMatch
from logsentinel.tracker import IPTracker


class TestIPTracker(unittest.TestCase):
    def setUp(self):
        self.tracker = IPTracker(threshold=3, time_window=60, whitelist=["127.0.0.1", "10.0.0.0/8"])
        self.sample_threat = ThreatMatch("SQLi", "TestRule", "HIGH", "' OR 1=1", "URI")

    def test_threshold_trigger(self):
        ip = "198.51.100.5"
        t0 = 1000.0

        # Offense 1
        ban, count = self.tracker.record_offense(ip, self.sample_threat, current_time=t0)
        self.assertFalse(ban)
        self.assertEqual(count, 1)

        # Offense 2
        ban, count = self.tracker.record_offense(ip, self.sample_threat, current_time=t0 + 10)
        self.assertFalse(ban)
        self.assertEqual(count, 2)

        # Offense 3 -> Should trigger ban!
        ban, count = self.tracker.record_offense(ip, self.sample_threat, current_time=t0 + 20)
        self.assertTrue(ban)
        self.assertEqual(count, 3)
        self.assertTrue(self.tracker.is_banned(ip))

        # Offense 4 -> Already banned, should NOT trigger ban again
        ban, count = self.tracker.record_offense(ip, self.sample_threat, current_time=t0 + 25)
        self.assertFalse(ban)

    def test_sliding_window_expiration(self):
        ip = "198.51.100.6"
        t0 = 1000.0

        # Offense 1 at t0
        self.tracker.record_offense(ip, self.sample_threat, current_time=t0)

        # Offense 2 at t0 + 10s
        self.tracker.record_offense(ip, self.sample_threat, current_time=t0 + 10)

        # Offense 3 at t0 + 75s (t0 and t0+10s have expired outside 60s window!)
        ban, count = self.tracker.record_offense(ip, self.sample_threat, current_time=t0 + 75)
        self.assertFalse(ban)
        self.assertEqual(count, 1)  # Only the new offense remains in the window

    def test_whitelist_protection(self):
        # 127.0.0.1 is whitelisted
        for _ in range(10):
            ban, count = self.tracker.record_offense("127.0.0.1", self.sample_threat)
            self.assertFalse(ban)
            self.assertEqual(count, 0)
        self.assertFalse(self.tracker.is_banned("127.0.0.1"))

        # 10.1.2.3 is within 10.0.0.0/8 CIDR
        ban, count = self.tracker.record_offense("10.1.2.3", self.sample_threat)
        self.assertFalse(ban)
        self.assertEqual(count, 0)
