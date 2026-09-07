#!/usr/bin/env python3
"""Simulated traffic generator to produce live Nginx/Apache logs with attacks."""

import argparse
import random
import time
from datetime import datetime, timezone

BENIGN_PATHS = [
    "/",
    "/index.html",
    "/about.html",
    "/contact",
    "/css/style.css",
    "/js/app.js",
    "/images/logo.png",
    "/api/v1/products?category=electronics&page=1",
    "/api/v1/cart/items",
    "/blog/post/how-to-secure-nginx",
    "/favicon.ico",
]

BENIGN_IPS = [
    "93.184.216.34",
    "151.101.65.140",
    "104.244.42.1",
    "172.217.16.206",
]

ATTACK_SCENARIOS = [
    {
        "name": "SQL Injection (Attacker IP 198.51.100.25)",
        "ip": "198.51.100.25",
        "requests": [
            "/products?id=1%27%20OR%201=1--",
            "/search?q=%27%20UNION%20SELECT%20null%2Cusername%2Cpassword%20FROM%20users--",
            "/login?user=admin%27%20OR%20%271%27=%271&pass=foo",
            "/api/items?cat=1;%20DROP%20TABLE%20sessions--",
        ],
    },
    {
        "name": "XSS Payloads (Attacker IP 203.0.113.88)",
        "ip": "203.0.113.88",
        "requests": [
            "/comments?msg=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E",
            "/search?query=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
            "/profile?bio=javascript%3Aalert(1)",
            "/forum?post=%3Ciframe%20src%3D%22http%3A%2F%2Fevil.com%22%3E",
        ],
    },
    {
        "name": "Path Traversal & Recon (Attacker IP 198.51.100.99)",
        "ip": "198.51.100.99",
        "requests": [
            "/download?file=../../../../etc/passwd",
            "/.env",
            "/wp-config.php",
            "/.git/config",
            "/cgi-bin/test-cgi?cmd=;cat%20/etc/passwd",
        ],
    },
    {
        "name": "Whitelisted Admin Scan (IP 127.0.0.1 - Should NOT be banned)",
        "ip": "127.0.0.1",
        "requests": [
            "/test?id=%27%20OR%201=1--",
            "/test?q=%3Cscript%3Ealert(1)%3C/script%3E",
            "/test?file=../../../../etc/passwd",
            "/test?file=../../../../etc/passwd",
        ],
    },
]


def format_combined_log(ip: str, path: str, status: int = 200, size: int = 1420, method: str = "GET") -> str:
    now_str = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
    referer = "https://example.com/"
    return f'{ip} - - [{now_str}] "{method} {path} HTTP/1.1" {status} {size} "{referer}" "{user_agent}"'


def simulate_stream(log_file: str, delay: float = 0.3):
    print(f"Starting simulated traffic generation into '{log_file}' (delay: {delay}s)...")
    with open(log_file, "a", encoding="utf-8") as f:
        # 1. First send some benign requests
        print(">> Generating initial benign traffic...")
        for _ in range(5):
            ip = random.choice(BENIGN_IPS)
            path = random.choice(BENIGN_PATHS)
            line = format_combined_log(ip, path)
            f.write(line + "\n")
            f.flush()
            time.sleep(delay)

        # 2. Iterate through attack scenarios
        for scenario in ATTACK_SCENARIOS:
            print(f">> Triggering Scenario: {scenario['name']}")
            for path in scenario["requests"]:
                # Mixed with occasional benign request from other users
                if random.random() > 0.5:
                    b_ip = random.choice(BENIGN_IPS)
                    b_path = random.choice(BENIGN_PATHS)
                    f.write(format_combined_log(b_ip, b_path) + "\n")

                line = format_combined_log(scenario["ip"], path, status=403 if "etc" in path else 200)
                f.write(line + "\n")
                f.flush()
                time.sleep(delay)

            time.sleep(0.5)

    print("Simulated traffic generation complete!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate live mock Apache/Nginx access log entries.")
    parser.add_argument("-f", "--log-file", default="access.log", help="Target access log file.")
    parser.add_argument("-d", "--delay", type=float, default=0.25, help="Delay in seconds between log entries.")
    args = parser.parse_args()
    simulate_stream(args.log_file, args.delay)
