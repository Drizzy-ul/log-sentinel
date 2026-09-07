"""Unit tests for the log parser."""

import unittest
from logsentinel.parser import parse_log_line, decode_url_recursive


class TestLogParser(unittest.TestCase):
    def test_parse_combined_format(self):
        line = '192.168.1.100 - frank [07/Sep/2026:12:34:56 +0000] "GET /index.php?user=admin HTTP/1.1" 200 4520 "https://google.com" "Mozilla/5.0"'
        entry = parse_log_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.ip, "192.168.1.100")
        self.assertEqual(entry.auth_user, "frank")
        self.assertEqual(entry.method, "GET")
        self.assertEqual(entry.request_uri, "/index.php?user=admin")
        self.assertEqual(entry.status_code, 200)
        self.assertEqual(entry.bytes_sent, 4520)
        self.assertEqual(entry.referer, "https://google.com")
        self.assertEqual(entry.user_agent, "Mozilla/5.0")

    def test_parse_clf_format_without_referer(self):
        line = '10.0.0.1 - - [07/Sep/2026:12:00:00 +0000] "POST /login HTTP/1.0" 401 128'
        entry = parse_log_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.ip, "10.0.0.1")
        self.assertEqual(entry.method, "POST")
        self.assertEqual(entry.status_code, 401)
        self.assertEqual(entry.bytes_sent, 128)

    def test_url_decoding(self):
        # Double URL encoded string: %2527 -> %27 -> '
        raw = "/search?q=%2527%20OR%201=1--"
        decoded = decode_url_recursive(raw)
        self.assertEqual(decoded, "/search?q=' OR 1=1--")

    def test_ignore_comments_and_empty(self):
        self.assertIsNone(parse_log_line(""))
        self.assertIsNone(parse_log_line("   "))
        self.assertIsNone(parse_log_line("# This is a comment"))
