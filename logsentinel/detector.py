"""Attack detection engine using regular expressions to detect web application attacks."""

import re
from dataclasses import dataclass
from typing import List, Optional
from logsentinel.parser import LogEntry


@dataclass
class ThreatMatch:
    category: str
    rule_name: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    matched_text: str
    matched_target: str  # URI, USER_AGENT, REFERER


@dataclass
class Rule:
    category: str
    name: str
    pattern: re.Pattern
    severity: str
    description: str


RULES: List[Rule] = [
    # SQL Injection
    Rule(
        category="SQLi",
        name="SQLi_Union_Select",
        pattern=re.compile(r"\bUNION(\s+ALL)?\s+SELECT\b", re.IGNORECASE),
        severity="CRITICAL",
        description="SQL Injection UNION SELECT statement",
    ),
    Rule(
        category="SQLi",
        name="SQLi_Boolean_Bypass",
        pattern=re.compile(r"(\x27|\x22)\s*(OR|AND)\s*(\x27?\d+\x27?|\w+)\s*=\s*(\x27?\d+\x27?|\w+)|(\x27|\x22)\s*(OR|AND)\s*1\s*=\s*1", re.IGNORECASE),
        severity="HIGH",
        description="SQL Injection boolean-based authentication bypass",
    ),
    Rule(
        category="SQLi",
        name="SQLi_Stacked_Or_DDL",
        pattern=re.compile(r"(;|\b)\s*(DROP|TRUNCATE|ALTER)\s+(TABLE|DATABASE)\b", re.IGNORECASE),
        severity="CRITICAL",
        description="SQL Injection destructive DDL command",
    ),
    Rule(
        category="SQLi",
        name="SQLi_Time_Delay",
        pattern=re.compile(r"\b(WAITFOR\s+DELAY|SLEEP\s*\(\s*\d+\s*\)|BENCHMARK\s*\(|PG_SLEEP\s*\()", re.IGNORECASE),
        severity="HIGH",
        description="Blind SQL Injection time delay function",
    ),
    Rule(
        category="SQLi",
        name="SQLi_Information_Schema",
        pattern=re.compile(r"\b(INFORMATION_SCHEMA|INTO\s+(OUTFILE|DUMPFILE)|LOAD_FILE\s*\()\b", re.IGNORECASE),
        severity="CRITICAL",
        description="SQL Injection metadata or filesystem access",
    ),
    Rule(
        category="SQLi",
        name="SQLi_Inline_Comment",
        pattern=re.compile(r"(\b(SELECT|INSERT|UPDATE|DELETE)\b.*(--|/\*|#))|(\bOR\b.*--)", re.IGNORECASE),
        severity="MEDIUM",
        description="SQL comment evasion syntax",
    ),

    # Cross-Site Scripting (XSS)
    Rule(
        category="XSS",
        name="XSS_Script_Tag",
        pattern=re.compile(r"<script\b[^>]*>", re.IGNORECASE),
        severity="HIGH",
        description="Cross-Site Scripting <script> tag injection",
    ),
    Rule(
        category="XSS",
        name="XSS_Javascript_URI",
        pattern=re.compile(r"\b(javascript|vbscript|data):[\s\S]*", re.IGNORECASE),
        severity="HIGH",
        description="Cross-Site Scripting pseudo-protocol scheme",
    ),
    Rule(
        category="XSS",
        name="XSS_Event_Handler",
        pattern=re.compile(r"\bon(load|error|click|mouseover|mouseenter|focus|blur|submit|change|input)\s*=", re.IGNORECASE),
        severity="HIGH",
        description="XSS HTML event handler injection",
    ),
    Rule(
        category="XSS",
        name="XSS_Dangerous_Tags",
        pattern=re.compile(r"<(iframe|img|svg|body|object|embed|audio|video|link|meta)\b[^>]*?(src|href|onload|onerror)\s*=", re.IGNORECASE),
        severity="MEDIUM",
        description="XSS payload inside HTML media or embedding tags",
    ),
    Rule(
        category="XSS",
        name="XSS_DOM_Cookie_Stealing",
        pattern=re.compile(r"\b(document\.(cookie|domain|location)|alert\s*\(|prompt\s*\(|confirm\s*\()", re.IGNORECASE),
        severity="HIGH",
        description="XSS DOM manipulation or execution call",
    ),

    # Path Traversal & LFI
    Rule(
        category="PathTraversal",
        name="Traversal_DotDotSlash",
        pattern=re.compile(r"(\.\./|\.\.\\)", re.IGNORECASE),
        severity="HIGH",
        description="Directory traversal dot-dot-slash sequence",
    ),
    Rule(
        category="PathTraversal",
        name="Traversal_Sensitive_Files",
        pattern=re.compile(r"(/etc/(passwd|shadow|hosts|issue|nginx|apache2)|windows/win\.ini|windows/system32)", re.IGNORECASE),
        severity="CRITICAL",
        description="Path traversal targeting critical operating system files",
    ),
    Rule(
        category="PathTraversal",
        name="Traversal_PHP_Wrappers",
        pattern=re.compile(r"(php://filter|php://input|data://text|proc/self/(environ|cmdline|cwd))", re.IGNORECASE),
        severity="CRITICAL",
        description="LFI via PHP stream wrapper or proc filesystem",
    ),

    # Command Injection / RCE
    Rule(
        category="RCE",
        name="RCE_Chained_Commands",
        pattern=re.compile(r"(;|\|\||&&|`)\s*(cat|ls|id|whoami|pwd|uname|nc|netcat|curl|wget|bash|sh|cmd|powershell)\b", re.IGNORECASE),
        severity="CRITICAL",
        description="OS command injection separator followed by system binary",
    ),
    Rule(
        category="RCE",
        name="RCE_Command_Substitution",
        pattern=re.compile(r"\$\([^\)]+\)", re.IGNORECASE),
        severity="CRITICAL",
        description="Shell command substitution $(...) pattern",
    ),
    Rule(
        category="RCE",
        name="RCE_Shell_Binaries",
        pattern=re.compile(r"(/bin/(sh|bash|zsh|dash)|powershell(\.exe)?|cmd(\.exe)?)", re.IGNORECASE),
        severity="CRITICAL",
        description="Direct invocation of shell executable",
    ),

    # Reconnaissance & Probing
    Rule(
        category="Probing",
        name="Probe_Sensitive_Configs",
        pattern=re.compile(r"(/\.(env|git|svn|htaccess|htpasswd|bash_history)|/wp-config\.php|/config\.(json|yml|yaml)|/web\.config)", re.IGNORECASE),
        severity="HIGH",
        description="Scanning for exposed configuration or version control files",
    ),
    Rule(
        category="Probing",
        name="Probe_Admin_Panels",
        pattern=re.compile(r"(/phpmyadmin|/adminer|/manager/html|/actuator/env)", re.IGNORECASE),
        severity="MEDIUM",
        description="Scanning for database management or application admin consoles",
    ),
]


class AttackDetector:
    """Evaluates parsed log entries against attack signatures."""

    def __init__(self, rules: Optional[List[Rule]] = None):
        self.rules = rules if rules is not None else RULES

    def analyze(self, entry: LogEntry) -> Optional[ThreatMatch]:
        """Inspect URI, User-Agent, and Referer of a log entry for attack patterns."""
        targets = [
            ("URI", entry.decoded_uri),
            ("USER_AGENT", entry.user_agent),
            ("REFERER", entry.referer),
        ]

        for target_name, target_value in targets:
            if not target_value or target_value == "-":
                continue

            for rule in self.rules:
                match = rule.pattern.search(target_value)
                if match:
                    matched_str = match.group(0)
                    return ThreatMatch(
                        category=rule.category,
                        rule_name=rule.name,
                        severity=rule.severity,
                        matched_text=matched_str,
                        matched_target=target_name,
                    )

        return None
