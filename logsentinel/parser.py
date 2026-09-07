"""Log parser for Nginx and Apache Common/Combined log formats."""

import re
import urllib.parse
from dataclasses import dataclass
from typing import Optional


@dataclass
class LogEntry:
    ip: str
    ident: str
    auth_user: str
    timestamp: str
    method: str
    request_uri: str
    decoded_uri: str
    protocol: str
    status_code: int
    bytes_sent: int
    referer: str
    user_agent: str
    raw_line: str


# Regex matching Combined Log Format and Common Log Format (CLF)
# Example: 192.168.1.50 - - [07/Sep/2026:12:00:00 +0000] "GET /index.php?id=1 HTTP/1.1" 200 4523 "http://example.com" "Mozilla/5.0"
COMBINED_LOG_REGEX = re.compile(
    r'^(\S+)\s+'                  # 1: Client IP
    r'(\S+)\s+'                  # 2: Ident
    r'(\S+)\s+'                  # 3: Auth user
    r'\[([^\]]+)\]\s+'          # 4: Timestamp
    r'"(\S+)\s+'                 # 5: HTTP Method
    r'(.*?)(?:\s+(\S+))?"\s+'    # 6: Request URI, 7: Protocol (optional)
    r'(\d{3})\s+'                # 8: HTTP Status Code
    r'(\S+)'                      # 9: Bytes sent (or -)
    r'(?:\s+"([^"]*)"\s+"([^"]*)")?' # 10: Referer (optional), 11: User-Agent (optional)
)


def decode_url_recursive(url: str, max_depth: int = 3) -> str:
    """Iteratively percent-decode URLs to unmask double/triple URL encoded attack payloads."""
    current = url
    for _ in range(max_depth):
        decoded = urllib.parse.unquote(current)
        if decoded == current:
            break
        current = decoded
    return current


def parse_log_line(line: str) -> Optional[LogEntry]:
    """Parse a single raw log row into a structured LogEntry object."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    match = COMBINED_LOG_REGEX.match(line)
    if not match:
        return None

    ip, ident, auth_user, timestamp, method, uri, protocol, status_str, bytes_str, referer, user_agent = match.groups()

    try:
        status_code = int(status_str)
    except ValueError:
        status_code = 0

    try:
        bytes_sent = int(bytes_str) if bytes_str and bytes_str != "-" else 0
    except ValueError:
        bytes_sent = 0

    decoded_uri = decode_url_recursive(uri)

    return LogEntry(
        ip=ip,
        ident=ident or "-",
        auth_user=auth_user or "-",
        timestamp=timestamp,
        method=method.upper(),
        request_uri=uri,
        decoded_uri=decoded_uri,
        protocol=protocol or "HTTP/1.0",
        status_code=status_code,
        bytes_sent=bytes_sent,
        referer=referer or "-",
        user_agent=user_agent or "-",
        raw_line=line,
    )
