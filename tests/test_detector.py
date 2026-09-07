"""Unit tests for the attack detector."""

import unittest
from logsentinel.detector import AttackDetector
from logsentinel.parser import parse_log_line


class TestAttackDetector(unittest.TestCase):
    def setUp(self):
        self.detector = AttackDetector()

    def _check(self, uri: str, ua: str = "Mozilla/5.0"):
        line = f'198.51.100.1 - - [07/Sep/2026:12:00:00 +0000] "GET {uri} HTTP/1.1" 200 100 "-" "{ua}"'
        entry = parse_log_line(line)
        self.assertIsNotNone(entry)
        return self.detector.analyze(entry)

    def test_sqli_detection(self):
        # 1. OR 1=1
        threat = self._check("/login?user=admin%27%20OR%201=1--")
        self.assertIsNotNone(threat)
        self.assertEqual(threat.category, "SQLi")

        # 2. UNION SELECT
        threat = self._check("/items?cat=1%20UNION%20ALL%20SELECT%201,2,3--")
        self.assertIsNotNone(threat)
        self.assertEqual(threat.category, "SQLi")

        # 3. Time delay
        threat = self._check("/item?id=1;%20WAITFOR%20DELAY%20'0:0:5'--")
        self.assertIsNotNone(threat)
        self.assertEqual(threat.category, "SQLi")

    def test_xss_detection(self):
        # 1. Script tag
        threat = self._check("/page?q=%3Cscript%3Ealert(1)%3C/script%3E")
        self.assertIsNotNone(threat)
        self.assertEqual(threat.category, "XSS")

        # 2. Onerror handler
        threat = self._check("/avatar?name=%3Cimg%20src=x%20onerror=alert(1)%3E")
        self.assertIsNotNone(threat)
        self.assertEqual(threat.category, "XSS")

        # 3. Javascript: protocol
        threat = self._check("/redirect?url=javascript:alert(document.cookie)")
        self.assertIsNotNone(threat)
        self.assertEqual(threat.category, "XSS")

    def test_path_traversal_detection(self):
        threat = self._check("/view?file=../../../../etc/passwd")
        self.assertIsNotNone(threat)
        self.assertEqual(threat.category, "PathTraversal")

        threat = self._check("/read?path=..\\..\\windows\\win.ini")
        self.assertIsNotNone(threat)
        self.assertEqual(threat.category, "PathTraversal")

    def test_rce_detection(self):
        threat = self._check("/ping?ip=127.0.0.1;%20whoami")
        self.assertIsNotNone(threat)
        self.assertEqual(threat.category, "RCE")

        threat = self._check("/run?cmd=$(whoami)")
        self.assertIsNotNone(threat)
        self.assertEqual(threat.category, "RCE")

    def test_probing_detection(self):
        threat = self._check("/.env")
        self.assertIsNotNone(threat)
        self.assertEqual(threat.category, "Probing")

        threat = self._check("/wp-config.php")
        self.assertIsNotNone(threat)
        self.assertEqual(threat.category, "Probing")

    def test_user_agent_injection(self):
        threat = self._check("/normal-page", ua="() { :;}; /bin/bash -c 'id'")
        self.assertIsNotNone(threat)
        self.assertEqual(threat.category, "RCE")

    def test_benign_traffic_no_false_positives(self):
        benign_urls = [
            "/",
            "/index.html",
            "/products/item-1234",
            "/category/women-clothing?page=2&sort=asc",
            "/static/css/bootstrap.min.css",
            "/static/js/bundle.js?v=1.2.0",
            "/api/v2/orders?status=shipped",
        ]
        for url in benign_urls:
            threat = self._check(url)
            self.assertIsNone(threat, f"False positive detected on legitimate URL: {url}")
