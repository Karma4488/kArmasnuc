#!/usr/bin/env python3
"""
kArmasnuc — template-driven web detection scanner (Nuclei-inspired)
Part of the kArmas suite. Single-file build — no external template files,
no YAML dependency. Everything (engine + templates) lives in this script.

Passive/detection only: fingerprints exposed files, misconfigurations,
and missing security headers. Does NOT exploit, brute force credentials,
or send destructive payloads.

Requirements:
    pip install requests --break-system-packages

Usage:
    python3 kArmasnuc.py -u https://target.com
    python3 kArmasnuc.py -l targets.txt -c 40 -o results.json
    python3 kArmasnuc.py -u https://target.com -severity high,critical
    python3 kArmasnuc.py -u https://target.com -tags exposure,git
    python3 kArmasnuc.py -u https://target.com -list-templates
"""

import argparse
import concurrent.futures
import json
import os
import re
import sys
import time
import warnings
from urllib.parse import urljoin

import requests

warnings.filterwarnings("ignore")
requests.packages.urllib3.disable_warnings()

# ------------------------------------------------------------------ #
# Aesthetic
# ------------------------------------------------------------------ #
GREEN = "\033[92m"
DGREEN = "\033[32m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
GREY = "\033[90m"
RESET = "\033[0m"
BOLD = "\033[1m"

BANNER = f"""{GREEN}{BOLD}
        ██╗  ██╗ █████╗ ██████╗ ███╗   ███╗ █████╗ ███████╗
        ██║ ██╔╝██╔══██╗██╔══██╗████╗ ████║██╔══██╗██╔════╝
        █████╔╝ ███████║██████╔╝██╔████╔██║███████║███████╗
        ██╔═██╗ ██╔══██║██╔══██╗██║╚██╔╝██║██╔══██║╚════██║
        ██║  ██╗██║  ██║██║  ██║██║ ╚═╝ ██║██║  ██║███████║
        ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝
{DGREEN}                     n  u  c  ── v2.0 (single-file)
{GREY}              We Are Legion // template scanning engine{RESET}
"""

SEVERITY_COLOR = {
    "info": CYAN,
    "low": GREEN,
    "medium": YELLOW,
    "high": RED,
    "critical": BOLD + RED,
}

# ------------------------------------------------------------------ #
# Embedded templates
# Same structure that used to live in templates/*.yaml, now inline as
# native Python dicts. Add new checks by appending to this list — no
# separate files needed.
# ------------------------------------------------------------------ #
TEMPLATES = [
    {
        "id": "git-config-exposure",
        "info": {"name": "Exposed .git/config", "severity": "high", "tags": "exposure,git,config"},
        "http": [{
            "method": "GET",
            "path": ["/.git/config"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["[core]", "repositoryformatversion"]},
            ],
        }],
    },
    {
        "id": "dotenv-exposure",
        "info": {"name": "Exposed .env file", "severity": "critical", "tags": "exposure,config,secrets"},
        "http": [{
            "method": "GET",
            "path": ["/.env"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r"(?i)(DB_PASSWORD|APP_KEY|SECRET_KEY|API_KEY|AWS_ACCESS_KEY_ID)\s*="]},
            ],
            "extractors": [
                {"regex": [r"(?i)([A-Z0-9_]+_KEY|DB_PASSWORD|SECRET_KEY)\s*=\s*(\S+)"]},
            ],
        }],
    },
    {
        "id": "wp-config-exposure",
        "info": {"name": "Exposed wp-config.php (readable source)", "severity": "critical",
                  "tags": "exposure,wordpress,secrets"},
        "http": [{
            "method": "GET",
            "path": ["/wp-config.php~", "/wp-config.php.save", "/wp-config.php.old",
                     "/wp-config.php.orig", "/_wp-config.php"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["DB_PASSWORD", "define( 'DB_", "define('DB_"]},
            ],
        }],
    },
    {
        "id": "backup-files-exposure",
        "info": {"name": "Exposed backup / archive file", "severity": "medium", "tags": "exposure,backup,misconfig"},
        "http": [{
            "method": "GET",
            "path": ["/backup.zip", "/backup.tar.gz", "/site.zip", "/www.zip", "/db.sql",
                     "/dump.sql", "/database.sql", "/backup.sql", "/index.php.bak",
                     "/wp-config.php.bak", "/config.php.bak", "/.htpasswd"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "negative": True,
                 "regex": [r"(?i)<title>\s*(404|not found|error)"]},
            ],
        }],
    },
    {
        "id": "phpinfo-exposure",
        "info": {"name": "Exposed phpinfo() page", "severity": "medium", "tags": "exposure,php"},
        "http": [{
            "method": "GET",
            "path": ["/phpinfo.php", "/info.php", "/test.php", "/php_info.php"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["phpinfo()", "PHP Version"]},
            ],
        }],
    },
    {
        "id": "dsstore-exposure",
        "info": {"name": "Exposed .DS_Store file", "severity": "low", "tags": "exposure,misconfig"},
        "http": [{
            "method": "GET",
            "path": ["/.DS_Store"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "header",
                 "regex": [r"(?i)Content-Type:\s*application/octet-stream"]},
            ],
        }],
    },
    {
        "id": "directory-listing-enabled",
        "info": {"name": "Directory listing enabled", "severity": "medium", "tags": "misconfig,exposure"},
        "http": [{
            "method": "GET",
            "path": ["/", "/uploads/", "/backup/", "/files/", "/assets/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)<title>index of /", r"(?i)Parent Directory</a>"]},
            ],
        }],
    },
    {
        "id": "cors-wildcard-misconfig",
        "info": {"name": "Permissive CORS (Access-Control-Allow-Origin: *)", "severity": "medium",
                  "tags": "misconfig,cors"},
        "http": [{
            "method": "GET",
            "path": ["/"],
            "headers": {"Origin": "https://evil.kArmasnuc-test.example"},
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "header", "condition": "or",
                 "words": ["Access-Control-Allow-Origin: *", "access-control-allow-origin: *"]},
            ],
        }],
    },
    {
        "id": "missing-security-headers",
        "info": {"name": "Missing X-Frame-Options header (clickjacking exposure)", "severity": "low",
                  "tags": "misconfig,headers"},
        "http": [{
            "method": "GET",
            "path": ["/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "header_absent", "header": "X-Frame-Options"},
            ],
        }],
    },
    {
        "id": "missing-hsts",
        "info": {"name": "Missing Strict-Transport-Security header", "severity": "low",
                  "tags": "misconfig,headers,tls"},
        "http": [{
            "method": "GET",
            "path": ["/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "header_absent", "header": "Strict-Transport-Security"},
            ],
        }],
    },
    {
        "id": "verbose-error-disclosure",
        "info": {"name": "Verbose error page / stack trace disclosure", "severity": "low",
                  "tags": "misconfig,disclosure"},
        "http": [{
            "method": "GET",
            "path": ["/nonexistent-kArmasnuc-probe-path-xyz123"],
            "matchers-condition": "or",
            "matchers": [
                {"type": "regex", "part": "body",
                 "regex": [
                     r"(?i)Fatal error:.*on line",
                     r"(?i)Warning:.*in\s+/.*\.php",
                     r"(?i)Traceback \(most recent call last\)",
                     r"(?i)System\.Exception",
                     r"(?i)at\s+[\w.]+\([\w.]+\.java:\d+\)",
                 ]},
            ],
        }],
    },
    {
        "id": "wordpress-detect",
        "info": {"name": "WordPress installation detected", "severity": "info", "tags": "fingerprint,cms,wordpress"},
        "http": [{
            "method": "GET",
            "path": ["/", "/wp-login.php"],
            "matchers-condition": "or",
            "matchers": [
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["wp-content", "wp-includes"]},
                {"type": "word", "part": "header", "words": ["X-Powered-By: PHP"]},
            ],
        }],
    },
    {
        "id": "server-header-disclosure",
        "info": {"name": "Server / tech version disclosed in headers", "severity": "info",
                  "tags": "fingerprint,headers"},
        "http": [{
            "method": "GET",
            "path": ["/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "regex", "part": "header", "condition": "or",
                 "regex": [r"(?i)Server:\s*[\w./-]+\d", r"(?i)X-Powered-By:\s*[\w./-]+"]},
            ],
            "extractors": [
                {"regex": [r"(?i)Server:\s*([\w./-]+)", r"(?i)X-Powered-By:\s*([\w./-]+)"]},
            ],
        }],
    },
    {
        "id": "cookies-missing-secure",
        "info": {"name": "Auth/session cookie without Secure flag", "severity": "medium", "tags": "misconfig,cookies,tls"},
        "http": [{
            "method": "GET",
            "path": ["/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "cookie_flag_missing", "flag": "Secure"},
            ],
            "extractors": [
                {"cookie_flag_missing": ["Secure"]},
            ],
        }],
    },
    {
        "id": "cookies-missing-httponly",
        "info": {"name": "Auth/session cookie without HttpOnly flag", "severity": "medium", "tags": "misconfig,cookies"},
        "http": [{
            "method": "GET",
            "path": ["/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "cookie_flag_missing", "flag": "HttpOnly"},
            ],
            "extractors": [
                {"cookie_flag_missing": ["HttpOnly"]},
            ],
        }],
    },
    {
        "id": "cookies-missing-samesite",
        "info": {"name": "Auth/session cookie without SameSite attribute", "severity": "medium", "tags": "misconfig,cookies,csrf"},
        "http": [{
            "method": "GET",
            "path": ["/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "cookie_flag_missing", "flag": "SameSite"},
            ],
            "extractors": [
                {"cookie_flag_missing": ["SameSite"]},
            ],
        }],
    },

    # ------------------------------------------------------------------ #
    # Exposed config / secret files
    # ------------------------------------------------------------------ #
    {
        "id": "htaccess-exposure",
        "info": {"name": "Exposed .htaccess file", "severity": "medium", "tags": "exposure,config,apache"},
        "http": [{
            "method": "GET",
            "path": ["/.htaccess"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)RewriteEngine", r"(?i)AuthType", r"(?i)Options\s+(All|Indexes|-Indexes)"]},
            ],
        }],
    },
    {
        "id": "web-config-exposure",
        "info": {"name": "Exposed web.config file (IIS)", "severity": "high", "tags": "exposure,config,iis"},
        "http": [{
            "method": "GET",
            "path": ["/web.config", "/Web.config"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)<configuration>", r"(?i)<connectionStrings>", r"(?i)<appSettings>"]},
            ],
        }],
    },
    {
        "id": "config-yml-exposure",
        "info": {"name": "Exposed YAML config file", "severity": "high", "tags": "exposure,config,secrets"},
        "http": [{
            "method": "GET",
            "path": ["/config.yml", "/config.yaml", "/app/config.yml",
                     "/application.yml", "/application.yaml", "/settings.yml"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)(password|secret|api_key|database)\s*:", r"(?i)(host|port|user)\s*:"]},
            ],
        }],
    },
    {
        "id": "credentials-json-exposure",
        "info": {"name": "Exposed credentials.json / service account key", "severity": "critical",
                  "tags": "exposure,config,secrets,cloud"},
        "http": [{
            "method": "GET",
            "path": ["/credentials.json", "/service-account.json", "/google-credentials.json",
                     "/gcp-credentials.json", "/firebase-adminsdk.json"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"private_key"', r'"client_email"', r'"type"\s*:\s*"service_account"']},
            ],
        }],
    },
    {
        "id": "npmrc-exposure",
        "info": {"name": "Exposed .npmrc file (may contain auth tokens)", "severity": "high",
                  "tags": "exposure,config,secrets,npm"},
        "http": [{
            "method": "GET",
            "path": ["/.npmrc"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)_authToken", r"(?i)//registry\.npmjs\.org/:", r"(?i)//npm\.pkg\.github\.com/:"]},
            ],
        }],
    },
    {
        "id": "aws-credentials-exposure",
        "info": {"name": "Exposed AWS credentials file", "severity": "critical",
                  "tags": "exposure,config,secrets,aws,cloud"},
        "http": [{
            "method": "GET",
            "path": ["/.aws/credentials", "/.aws/config"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"aws_access_key_id", r"aws_secret_access_key", r"\[default\]"]},
            ],
            "extractors": [
                {"regex": [r"aws_access_key_id\s*=\s*(\S+)", r"aws_secret_access_key\s*=\s*(\S+)"]},
            ],
        }],
    },
    {
        "id": "bash-history-exposure",
        "info": {"name": "Exposed .bash_history file", "severity": "medium",
                  "tags": "exposure,config,misconfig"},
        "http": [{
            "method": "GET",
            "path": ["/.bash_history"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)(sudo|ssh|mysql|psql|curl|wget|chmod)\s", r"(?i)(--password|--user|-p\s)"]},
            ],
        }],
    },
    {
        "id": "ssh-private-key-exposure",
        "info": {"name": "Exposed SSH private key", "severity": "critical",
                  "tags": "exposure,secrets,ssh"},
        "http": [{
            "method": "GET",
            "path": ["/.ssh/id_rsa", "/.ssh/id_ecdsa", "/.ssh/id_ed25519", "/.ssh/id_dsa",
                     "/id_rsa", "/id_ecdsa"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "words": ["-----BEGIN"]},
            ],
        }],
    },
    {
        "id": "private-key-pem-exposure",
        "info": {"name": "Exposed PEM / certificate private key", "severity": "critical",
                  "tags": "exposure,secrets,tls"},
        "http": [{
            "method": "GET",
            "path": ["/server.key", "/server.pem", "/private.key", "/private.pem",
                     "/cert.key", "/ssl.key", "/ssl.pem"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"]},
            ],
        }],
    },
    {
        "id": "env-backup-exposure",
        "info": {"name": "Exposed .env backup / alternate names", "severity": "critical",
                  "tags": "exposure,config,secrets"},
        "http": [{
            "method": "GET",
            "path": ["/.env.bak", "/.env.backup", "/.env.old", "/.env.orig",
                     "/.env.example", "/.env.production", "/.env.staging", "/.env.local"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r"(?i)(DB_PASSWORD|APP_KEY|SECRET_KEY|API_KEY|DATABASE_URL)\s*="]},
            ],
        }],
    },
    {
        "id": "composer-json-exposure",
        "info": {"name": "Exposed composer.json (PHP dependency manifest)", "severity": "info",
                  "tags": "exposure,fingerprint,php"},
        "http": [{
            "method": "GET",
            "path": ["/composer.json", "/composer.lock"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"require"', r'"require-dev"', r'"packages"']},
            ],
        }],
    },
    {
        "id": "package-json-exposure",
        "info": {"name": "Exposed package.json (Node.js manifest)", "severity": "info",
                  "tags": "exposure,fingerprint,nodejs"},
        "http": [{
            "method": "GET",
            "path": ["/package.json", "/package-lock.json"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"dependencies"', r'"devDependencies"', r'"scripts"']},
            ],
        }],
    },
    {
        "id": "htpasswd-exposure",
        "info": {"name": "Exposed .htpasswd file", "severity": "high",
                  "tags": "exposure,config,apache,auth"},
        "http": [{
            "method": "GET",
            "path": ["/.htpasswd"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r"(?i)[^:]+:\$apr1\$", r"(?i)[^:]+:\{SHA\}"]},
            ],
        }],
    },

    # ------------------------------------------------------------------ #
    # Admin, status, health, and debug endpoints
    # ------------------------------------------------------------------ #
    {
        "id": "phpmyadmin-panel",
        "info": {"name": "phpMyAdmin panel exposed", "severity": "high",
                  "tags": "exposure,panel,phpmyadmin,database"},
        "http": [{
            "method": "GET",
            "path": ["/phpmyadmin/", "/phpMyAdmin/", "/pma/", "/dbadmin/", "/phpmyadmin"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["phpMyAdmin", "Welcome to phpMyAdmin", "pma_"]},
            ],
        }],
    },
    {
        "id": "adminer-panel",
        "info": {"name": "Adminer database management panel exposed", "severity": "high",
                  "tags": "exposure,panel,adminer,database"},
        "http": [{
            "method": "GET",
            "path": ["/adminer.php", "/adminer/", "/adminer"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["adminer", "Adminer", "Login - Adminer"]},
            ],
        }],
    },
    {
        "id": "admin-panel-detect",
        "info": {"name": "Generic admin panel detected", "severity": "medium",
                  "tags": "exposure,panel,admin"},
        "http": [{
            "method": "GET",
            "path": ["/admin", "/admin/", "/admin.php", "/administrator/",
                     "/admin/login", "/admin/index.php", "/admin/dashboard"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)<title>.*admin", r"(?i)(admin\s*(panel|dashboard|login|area))"]},
            ],
        }],
    },
    {
        "id": "spring-actuator-exposure",
        "info": {"name": "Spring Boot Actuator endpoints exposed", "severity": "high",
                  "tags": "exposure,springboot,actuator,java"},
        "http": [{
            "method": "GET",
            "path": ["/actuator", "/actuator/env", "/actuator/health",
                     "/actuator/metrics", "/actuator/beans", "/actuator/mappings",
                     "/actuator/trace", "/actuator/httptrace", "/actuator/loggers"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"_links"', r'"status"\s*:\s*"UP"', r'"activeProfiles"',
                           r'"beans"', r'"mappings"']},
            ],
        }],
    },
    {
        "id": "health-endpoint-info-disclosure",
        "info": {"name": "Health/status endpoint with version or component info", "severity": "low",
                  "tags": "exposure,health,fingerprint"},
        "http": [{
            "method": "GET",
            "path": ["/health", "/healthz", "/health/live", "/health/ready",
                     "/ping", "/status", "/alive", "/readiness", "/liveness"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"status"\s*:', r"(?i)(healthy|up|ok|running)\b", r'"version"\s*:']},
            ],
        }],
    },
    {
        "id": "debug-endpoint-exposure",
        "info": {"name": "Debug / development endpoint exposed", "severity": "high",
                  "tags": "exposure,debug,misconfig"},
        "http": [{
            "method": "GET",
            "path": ["/debug", "/_debug", "/debug/", "/console",
                     "/rails/info/properties", "/rails/info", "/_profiler",
                     "/app_dev.php", "/app_dev.php/_profiler"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)(debug|profiler|stack trace|app_dev)", r"(?i)Symfony Profiler"]},
            ],
        }],
    },
    {
        "id": "tomcat-manager-panel",
        "info": {"name": "Apache Tomcat Manager panel exposed", "severity": "critical",
                  "tags": "exposure,panel,tomcat,java"},
        "http": [{
            "method": "GET",
            "path": ["/manager/html", "/manager/", "/manager",
                     "/host-manager/html", "/host-manager/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200, 401, 403]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["Tomcat Manager", "Tomcat Web Application Manager", "Apache Tomcat"]},
            ],
        }],
    },
    {
        "id": "laravel-debug-exposure",
        "info": {"name": "Laravel debug / Ignition error page exposed", "severity": "high",
                  "tags": "exposure,debug,laravel,php"},
        "http": [{
            "method": "GET",
            "path": ["/_ignition/health-check", "/_ignition/execute-solution"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200, 422]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)ignition", r'"canExecuteSolutions"', r"(?i)Facade\\Ignition"]},
            ],
        }],
    },
    {
        "id": "django-debug-enabled",
        "info": {"name": "Django DEBUG mode enabled (detailed error page)", "severity": "high",
                  "tags": "exposure,debug,django,python"},
        "http": [{
            "method": "GET",
            "path": ["/kArmasnuc-probe-django-debug-xyz123"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [404]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["Django tried these URL patterns",
                           "You're seeing this error because you have",
                           "Using the URLconf defined in"]},
            ],
        }],
    },

    # ------------------------------------------------------------------ #
    # API docs and schema exposure
    # ------------------------------------------------------------------ #
    {
        "id": "swagger-ui-exposure",
        "info": {"name": "Swagger UI / OpenAPI documentation exposed", "severity": "medium",
                  "tags": "exposure,api,swagger,openapi"},
        "http": [{
            "method": "GET",
            "path": ["/swagger-ui.html", "/swagger-ui/", "/swagger-ui/index.html",
                     "/swagger/", "/api/swagger-ui.html", "/docs/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["swagger-ui", "SwaggerUI", "Swagger UI"]},
            ],
        }],
    },
    {
        "id": "openapi-spec-exposure",
        "info": {"name": "OpenAPI / Swagger spec file exposed", "severity": "medium",
                  "tags": "exposure,api,swagger,openapi"},
        "http": [{
            "method": "GET",
            "path": ["/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
                     "/api-docs", "/api/swagger.json", "/v1/api-docs", "/v2/api-docs",
                     "/v3/api-docs"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"swagger"\s*:', r'"openapi"\s*:', r'"paths"\s*:',
                           r"swagger:\s*['\"]2\.", r"openapi:\s*['\"]3\."]},
            ],
        }],
    },
    {
        "id": "graphql-introspection",
        "info": {"name": "GraphQL endpoint with introspection enabled", "severity": "medium",
                  "tags": "exposure,api,graphql"},
        "http": [{
            "method": "GET",
            "path": ["/graphql?query={__schema{types{name}}}", "/graphiql",
                     "/graphql/console", "/api/graphql"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"__schema"', r'"__typename"', r'"types"\s*:', r"graphiql"]},
            ],
        }],
    },
    {
        "id": "redoc-api-exposure",
        "info": {"name": "ReDoc API documentation exposed", "severity": "info",
                  "tags": "exposure,api,openapi"},
        "http": [{
            "method": "GET",
            "path": ["/redoc", "/redoc/", "/api/redoc"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["redoc", "ReDoc", "redoc-container"]},
            ],
        }],
    },
    {
        "id": "jsonapi-schema-exposure",
        "info": {"name": "JSON:API or REST schema endpoint exposed", "severity": "info",
                  "tags": "exposure,api,fingerprint"},
        "http": [{
            "method": "GET",
            "path": ["/api/", "/api/v1/", "/api/v2/", "/api/v3/", "/rest/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"data"\s*:', r'"links"\s*:', r'"meta"\s*:', r'"endpoints"\s*:']},
            ],
        }],
    },
    {
        "id": "wsdl-exposure",
        "info": {"name": "Exposed WSDL (SOAP web service descriptor)", "severity": "medium",
                  "tags": "exposure,api,soap,wsdl"},
        "http": [{
            "method": "GET",
            "path": ["/service.wsdl", "/webservice.wsdl", "/?wsdl", "/ws?wsdl",
                     "/soap/wsdl", "/Services.asmx?wsdl"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["wsdl:definitions", "WSDL", "<definitions"]},
            ],
        }],
    },

    # ------------------------------------------------------------------ #
    # Setup / install leftovers
    # ------------------------------------------------------------------ #
    {
        "id": "install-php-leftover",
        "info": {"name": "Install/setup PHP script leftover", "severity": "high",
                  "tags": "exposure,misconfig,install"},
        "http": [{
            "method": "GET",
            "path": ["/install.php", "/setup.php", "/upgrade.php", "/update.php",
                     "/install/", "/setup/", "/wp-admin/install.php", "/install.sql",
                     "/config/install.php"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)(installation|setup|installer|upgrade|database setup)",
                           r"(?i)(DB_HOST|database_host|connection string)"]},
            ],
        }],
    },
    {
        "id": "readme-changelog-disclosure",
        "info": {"name": "README / CHANGELOG version disclosure", "severity": "info",
                  "tags": "exposure,fingerprint,disclosure"},
        "http": [{
            "method": "GET",
            "path": ["/README.txt", "/CHANGELOG.txt", "/CHANGELOG.md", "/CHANGELOG",
                     "/INSTALL.txt", "/VERSION.txt", "/RELEASE.txt", "/CHANGES.txt"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)version\s+\d+\.\d+", r"(?i)(changelog|release notes|changes in)",
                           r"(?i)(fixed|improved|added)\s+in\s+v?\d"]},
            ],
        }],
    },
    {
        "id": "license-file-disclosure",
        "info": {"name": "License file exposed (software fingerprint)", "severity": "info",
                  "tags": "exposure,fingerprint,disclosure"},
        "http": [{
            "method": "GET",
            "path": ["/LICENSE", "/LICENSE.txt", "/LICENSE.md"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)(MIT License|Apache License|GNU General Public License|BSD)",
                           r"(?i)Permission is hereby granted"]},
            ],
        }],
    },

    # ------------------------------------------------------------------ #
    # Version control / metadata exposure
    # ------------------------------------------------------------------ #
    {
        "id": "git-head-exposure",
        "info": {"name": "Exposed .git/HEAD file", "severity": "high",
                  "tags": "exposure,git,vcs"},
        "http": [{
            "method": "GET",
            "path": ["/.git/HEAD"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r"(?:ref: refs/heads/\w+|[0-9a-f]{40})"]},
            ],
            "extractors": [
                {"regex": [r"ref: refs/heads/(\w+)"]},
            ],
        }],
    },
    {
        "id": "svn-entries-exposure",
        "info": {"name": "Exposed Subversion (.svn/entries) metadata", "severity": "high",
                  "tags": "exposure,vcs,svn"},
        "http": [{
            "method": "GET",
            "path": ["/.svn/entries", "/.svn/wc.db"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)(svn|subversion)", r"(?i)working copy", r"this is a\s+svn"]},
            ],
        }],
    },
    {
        "id": "mercurial-hg-exposure",
        "info": {"name": "Exposed Mercurial (.hg) repository metadata", "severity": "high",
                  "tags": "exposure,vcs,mercurial"},
        "http": [{
            "method": "GET",
            "path": ["/.hg/", "/.hg/dirstate", "/.hg/hgrc"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)\[paths\]", r"(?i)default\s*=\s*http"]},
            ],
        }],
    },
    {
        "id": "git-log-exposure",
        "info": {"name": "Exposed .git/logs/HEAD (commit history)", "severity": "high",
                  "tags": "exposure,git,vcs"},
        "http": [{
            "method": "GET",
            "path": ["/.git/logs/HEAD"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r"[0-9a-f]{40}\s+[0-9a-f]{40}"]},
            ],
        }],
    },
    {
        "id": "git-packed-refs-exposure",
        "info": {"name": "Exposed .git/packed-refs (branch/tag listing)", "severity": "medium",
                  "tags": "exposure,git,vcs"},
        "http": [{
            "method": "GET",
            "path": ["/.git/packed-refs"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"[0-9a-f]{40}\s+refs/", r"# pack-refs"]},
            ],
        }],
    },

    # ------------------------------------------------------------------ #
    # Framework-specific disclosure artifacts
    # ------------------------------------------------------------------ #
    {
        "id": "laravel-log-exposure",
        "info": {"name": "Exposed Laravel application log", "severity": "high",
                  "tags": "exposure,laravel,php,log"},
        "http": [{
            "method": "GET",
            "path": ["/storage/logs/laravel.log", "/storage/logs/laravel-today.log",
                     "/app/storage/logs/laravel.log"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"\[20\d{2}-\d{2}-\d{2}", r"(?i)Illuminate\\", r"(?i)local\.ERROR"]},
            ],
        }],
    },
    {
        "id": "symfony-profiler-exposure",
        "info": {"name": "Symfony web profiler / debug toolbar exposed", "severity": "high",
                  "tags": "exposure,debug,symfony,php"},
        "http": [{
            "method": "GET",
            "path": ["/_profiler", "/_profiler/", "/_profiler/empty/search/results"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["Symfony Profiler", "sf-toolbar", "Profiler token"]},
            ],
        }],
    },
    {
        "id": "rails-info-properties",
        "info": {"name": "Rails /rails/info/properties exposed", "severity": "high",
                  "tags": "exposure,debug,rails,ruby"},
        "http": [{
            "method": "GET",
            "path": ["/rails/info/properties", "/rails/info/routes"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["Ruby Version", "Rails Version", "rails", "ActiveRecord"]},
            ],
        }],
    },
    {
        "id": "aspnet-trace-axd",
        "info": {"name": "ASP.NET Trace.axd diagnostic page exposed", "severity": "high",
                  "tags": "exposure,debug,aspnet,dotnet"},
        "http": [{
            "method": "GET",
            "path": ["/Trace.axd", "/trace.axd", "/WebResource.axd?d=bogus"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["Application Trace", "ASP.NET", "Request Details"]},
            ],
        }],
    },
    {
        "id": "wordpress-debug-log",
        "info": {"name": "Exposed WordPress debug.log", "severity": "medium",
                  "tags": "exposure,log,wordpress,php"},
        "http": [{
            "method": "GET",
            "path": ["/wp-content/debug.log", "/wp-debug.log", "/debug.log"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"\[20\d{2}-\d{2}-\d{2}", r"(?i)PHP (Fatal error|Warning|Notice|Deprecated)",
                           r"(?i)WordPress database error"]},
            ],
        }],
    },
    {
        "id": "joomla-configuration-backup",
        "info": {"name": "Exposed Joomla configuration backup", "severity": "critical",
                  "tags": "exposure,joomla,config,secrets"},
        "http": [{
            "method": "GET",
            "path": ["/configuration.php~", "/configuration.php.bak",
                     "/configuration.php.save", "/configuration.php.old"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["JConfig", "public $password", "public $db"]},
            ],
        }],
    },
    {
        "id": "drupal-settings-backup",
        "info": {"name": "Exposed Drupal settings backup", "severity": "critical",
                  "tags": "exposure,drupal,config,secrets"},
        "http": [{
            "method": "GET",
            "path": ["/sites/default/settings.php~", "/sites/default/settings.php.bak",
                     "/sites/default/default.settings.php"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["$databases", "database_default", "db_url"]},
            ],
        }],
    },
    {
        "id": "python-requirements-exposure",
        "info": {"name": "Exposed requirements.txt (Python dependencies)", "severity": "info",
                  "tags": "exposure,fingerprint,python"},
        "http": [{
            "method": "GET",
            "path": ["/requirements.txt", "/requirements/base.txt",
                     "/requirements/production.txt", "/Pipfile", "/Pipfile.lock"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)(django|flask|fastapi|sqlalchemy|requests)==\d",
                           r"(?i)\w+==\d+\.\d+"]},
            ],
        }],
    },

    # ------------------------------------------------------------------ #
    # Service dashboards / monitoring panels
    # ------------------------------------------------------------------ #
    {
        "id": "kibana-panel-exposure",
        "info": {"name": "Kibana dashboard exposed", "severity": "high",
                  "tags": "exposure,panel,kibana,elasticsearch"},
        "http": [{
            "method": "GET",
            "path": ["/app/kibana", "/kibana/", "/kibana"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["kibana", "Kibana", "kbn-", "kbnVersion"]},
            ],
        }],
    },
    {
        "id": "grafana-panel-exposure",
        "info": {"name": "Grafana dashboard exposed", "severity": "medium",
                  "tags": "exposure,panel,grafana,monitoring"},
        "http": [{
            "method": "GET",
            "path": ["/grafana", "/grafana/", "/grafana/login"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["Grafana", "grafana", "grafana-app"]},
            ],
        }],
    },
    {
        "id": "prometheus-metrics-exposure",
        "info": {"name": "Prometheus /metrics endpoint exposed", "severity": "medium",
                  "tags": "exposure,panel,prometheus,monitoring"},
        "http": [{
            "method": "GET",
            "path": ["/metrics", "/api/metrics", "/prometheus/metrics"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"# HELP\s+\w+", r"# TYPE\s+\w+", r"go_gc_duration_seconds"]},
            ],
        }],
    },
    {
        "id": "jenkins-panel-exposure",
        "info": {"name": "Jenkins CI panel exposed", "severity": "high",
                  "tags": "exposure,panel,jenkins,ci"},
        "http": [{
            "method": "GET",
            "path": ["/jenkins", "/jenkins/", "/jenkins/login"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200, 403]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["Jenkins", "Dashboard [Jenkins]", "jenkins-home"]},
            ],
        }],
    },
    {
        "id": "solr-admin-panel",
        "info": {"name": "Apache Solr admin panel exposed", "severity": "high",
                  "tags": "exposure,panel,solr,search"},
        "http": [{
            "method": "GET",
            "path": ["/solr/", "/solr/#/", "/solr/admin/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["Solr Admin", "solrconfig", "SolrCore"]},
            ],
        }],
    },
    {
        "id": "rabbitmq-management-panel",
        "info": {"name": "RabbitMQ management panel exposed", "severity": "high",
                  "tags": "exposure,panel,rabbitmq,mq"},
        "http": [{
            "method": "GET",
            "path": ["/#/", "/rabbitmq/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["RabbitMQ Management", "rabbitmq_management", "RabbitMQ"]},
            ],
        }],
    },
    {
        "id": "redis-commander-panel",
        "info": {"name": "Redis Commander / GUI panel exposed", "severity": "high",
                  "tags": "exposure,panel,redis,database"},
        "http": [{
            "method": "GET",
            "path": ["/redis-commander", "/redis/", "/redisinsight/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["Redis Commander", "RedisInsight", "redis-commander"]},
            ],
        }],
    },
    {
        "id": "elasticsearch-api-exposure",
        "info": {"name": "Elasticsearch API exposed without authentication", "severity": "critical",
                  "tags": "exposure,elasticsearch,database,api"},
        "http": [{
            "method": "GET",
            "path": ["/_cat/indices?v", "/_cluster/health", "/_nodes"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"cluster_name"', r'"status"\s*:\s*"(green|yellow|red)"',
                           r"(?i)index\s+health"]},
            ],
        }],
    },
    {
        "id": "consul-api-exposure",
        "info": {"name": "HashiCorp Consul API exposed", "severity": "high",
                  "tags": "exposure,consul,service-mesh,cloud"},
        "http": [{
            "method": "GET",
            "path": ["/v1/agent/self", "/v1/catalog/services", "/ui/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"Config"\s*:', r'"Member"\s*:', r'"Services"\s*:',
                           r"(?i)Consul"]},
            ],
        }],
    },
    {
        "id": "hawtio-panel-exposure",
        "info": {"name": "Hawtio Java management panel exposed", "severity": "high",
                  "tags": "exposure,panel,hawtio,java,jmx"},
        "http": [{
            "method": "GET",
            "path": ["/hawtio", "/hawtio/", "/hawtio/index.html"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["hawtio", "Hawtio"]},
            ],
        }],
    },

    # ------------------------------------------------------------------ #
    # Additional missing security headers
    # ------------------------------------------------------------------ #
    {
        "id": "missing-csp",
        "info": {"name": "Missing Content-Security-Policy header", "severity": "medium",
                  "tags": "misconfig,headers,csp"},
        "http": [{
            "method": "GET",
            "path": ["/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "header_absent", "header": "Content-Security-Policy"},
            ],
        }],
    },
    {
        "id": "missing-x-content-type-options",
        "info": {"name": "Missing X-Content-Type-Options header (MIME sniffing)", "severity": "low",
                  "tags": "misconfig,headers"},
        "http": [{
            "method": "GET",
            "path": ["/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "header_absent", "header": "X-Content-Type-Options"},
            ],
        }],
    },
    {
        "id": "missing-referrer-policy",
        "info": {"name": "Missing Referrer-Policy header", "severity": "low",
                  "tags": "misconfig,headers"},
        "http": [{
            "method": "GET",
            "path": ["/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "header_absent", "header": "Referrer-Policy"},
            ],
        }],
    },
    {
        "id": "missing-permissions-policy",
        "info": {"name": "Missing Permissions-Policy header", "severity": "info",
                  "tags": "misconfig,headers"},
        "http": [{
            "method": "GET",
            "path": ["/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "header_absent", "header": "Permissions-Policy"},
            ],
        }],
    },
    {
        "id": "missing-xcto-nosniff",
        "info": {"name": "X-Content-Type-Options not set to nosniff", "severity": "low",
                  "tags": "misconfig,headers"},
        "http": [{
            "method": "GET",
            "path": ["/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "header", "negative": True,
                 "regex": [r"(?i)X-Content-Type-Options:\s*nosniff"]},
            ],
        }],
    },
    {
        "id": "server-info-apache-php",
        "info": {"name": "Apache/PHP server-status or server-info page accessible", "severity": "medium",
                  "tags": "exposure,apache,php,fingerprint"},
        "http": [{
            "method": "GET",
            "path": ["/server-status", "/server-info"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)Apache Server Status", r"(?i)Apache Status",
                           r"(?i)Server Version:", r"(?i)Server uptime:"]},
            ],
        }],
    },

    # ------------------------------------------------------------------ #
    # Cloud / deployment config leakage
    # ------------------------------------------------------------------ #
    {
        "id": "docker-compose-exposure",
        "info": {"name": "Exposed docker-compose.yml file", "severity": "high",
                  "tags": "exposure,config,docker,cloud"},
        "http": [{
            "method": "GET",
            "path": ["/docker-compose.yml", "/docker-compose.yaml",
                     "/docker-compose.override.yml"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)services\s*:", r"(?i)image:\s*\w", r"(?i)container_name\s*:"]},
            ],
        }],
    },
    {
        "id": "dockerfile-exposure",
        "info": {"name": "Exposed Dockerfile", "severity": "medium",
                  "tags": "exposure,config,docker,cloud"},
        "http": [{
            "method": "GET",
            "path": ["/Dockerfile", "/docker/Dockerfile"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)FROM\s+\w", r"(?i)RUN\s+", r"(?i)ENV\s+"]},
            ],
        }],
    },
    {
        "id": "terraform-tfstate-exposure",
        "info": {"name": "Exposed Terraform state file (.tfstate)", "severity": "critical",
                  "tags": "exposure,config,terraform,cloud,secrets"},
        "http": [{
            "method": "GET",
            "path": ["/terraform.tfstate", "/terraform.tfstate.backup",
                     "/.terraform/terraform.tfstate"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"terraform_version"', r'"resources"\s*:', r'"outputs"\s*:']},
            ],
        }],
    },
    {
        "id": "kubernetes-config-exposure",
        "info": {"name": "Exposed Kubernetes configuration / manifest", "severity": "high",
                  "tags": "exposure,config,kubernetes,cloud"},
        "http": [{
            "method": "GET",
            "path": ["/kubeconfig", "/.kube/config", "/k8s-config.yaml",
                     "/deployment.yaml", "/kustomization.yaml"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)apiVersion\s*:", r"(?i)kind:\s*(Deployment|Service|Pod)",
                           r"(?i)clusters\s*:\s*\n\s*-"]},
            ],
        }],
    },
    {
        "id": "serverless-yml-exposure",
        "info": {"name": "Exposed serverless.yml (Serverless Framework config)", "severity": "high",
                  "tags": "exposure,config,serverless,cloud,aws"},
        "http": [{
            "method": "GET",
            "path": ["/serverless.yml", "/serverless.yaml"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)service\s*:", r"(?i)provider\s*:",
                           r"(?i)functions\s*:"]},
            ],
        }],
    },
    {
        "id": "cloudbuild-config-exposure",
        "info": {"name": "Exposed cloud build / CI config file", "severity": "low",
                  "tags": "exposure,config,cloud,ci"},
        "http": [{
            "method": "GET",
            "path": ["/cloudbuild.yaml", "/cloudbuild.yml", "/.travis.yml",
                     "/circle.yml", "/.circleci/config.yml", "/.github/workflows/main.yml",
                     "/Jenkinsfile", "/azure-pipelines.yml"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)(steps|jobs|pipelines|stages)\s*:",
                           r"(?i)(docker|image|script|run)\s*:"]},
            ],
        }],
    },
    {
        "id": "gcp-app-engine-config",
        "info": {"name": "Exposed GCP App Engine configuration (app.yaml)", "severity": "medium",
                  "tags": "exposure,config,cloud,gcp"},
        "http": [{
            "method": "GET",
            "path": ["/app.yaml", "/app.yml"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)runtime\s*:", r"(?i)service\s*:", r"(?i)env_variables\s*:"]},
            ],
        }],
    },

    # ------------------------------------------------------------------ #
    # Technology / framework fingerprinting
    # ------------------------------------------------------------------ #
    {
        "id": "drupal-detect",
        "info": {"name": "Drupal CMS detected", "severity": "info",
                  "tags": "fingerprint,cms,drupal"},
        "http": [{
            "method": "GET",
            "path": ["/", "/user/login"],
            "matchers-condition": "or",
            "matchers": [
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["Drupal.settings", "/sites/default/files", "drupal.js"]},
                {"type": "word", "part": "header", "words": ["X-Generator: Drupal"]},
            ],
        }],
    },
    {
        "id": "joomla-detect",
        "info": {"name": "Joomla CMS detected", "severity": "info",
                  "tags": "fingerprint,cms,joomla"},
        "http": [{
            "method": "GET",
            "path": ["/", "/administrator/"],
            "matchers-condition": "or",
            "matchers": [
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["/media/jui/", "Joomla!", "joomla.framework"]},
                {"type": "word", "part": "header", "words": ["X-Content-Encoded-By: Joomla"]},
            ],
        }],
    },
    {
        "id": "shopify-detect",
        "info": {"name": "Shopify e-commerce platform detected", "severity": "info",
                  "tags": "fingerprint,ecommerce,shopify"},
        "http": [{
            "method": "GET",
            "path": ["/"],
            "matchers-condition": "or",
            "matchers": [
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["cdn.shopify.com", "Shopify.theme", "myshopify.com"]},
            ],
        }],
    },
    {
        "id": "magento-detect",
        "info": {"name": "Magento e-commerce platform detected", "severity": "info",
                  "tags": "fingerprint,ecommerce,magento"},
        "http": [{
            "method": "GET",
            "path": ["/", "/admin/", "/magento_version"],
            "matchers-condition": "or",
            "matchers": [
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["Mage.Cookies", "Magento_Ui", "mage/cookies"]},
            ],
        }],
    },
    {
        "id": "nextjs-detect",
        "info": {"name": "Next.js framework detected", "severity": "info",
                  "tags": "fingerprint,nodejs,nextjs"},
        "http": [{
            "method": "GET",
            "path": ["/", "/_next/static/"],
            "matchers-condition": "or",
            "matchers": [
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["__NEXT_DATA__", "_next/static", "next/dist"]},
                {"type": "word", "part": "header", "words": ["x-powered-by: Next.js"]},
            ],
        }],
    },
    {
        "id": "angular-detect",
        "info": {"name": "Angular SPA detected", "severity": "info",
                  "tags": "fingerprint,nodejs,angular"},
        "http": [{
            "method": "GET",
            "path": ["/"],
            "matchers-condition": "or",
            "matchers": [
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["ng-version=", "ng-app=", "angular.min.js", "angular/core"]},
            ],
        }],
    },
    {
        "id": "react-detect",
        "info": {"name": "React SPA detected", "severity": "info",
                  "tags": "fingerprint,nodejs,react"},
        "http": [{
            "method": "GET",
            "path": ["/"],
            "matchers-condition": "or",
            "matchers": [
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["react.development.js", "react.production.min.js",
                           "data-reactroot", "data-reactid"]},
            ],
        }],
    },

    # ------------------------------------------------------------------ #
    # Miscellaneous exposure / misconfig
    # ------------------------------------------------------------------ #
    {
        "id": "crossdomain-xml-exposure",
        "info": {"name": "Permissive crossdomain.xml (Flash/legacy CORS)", "severity": "medium",
                  "tags": "exposure,misconfig,cors"},
        "http": [{
            "method": "GET",
            "path": ["/crossdomain.xml"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r'(?i)domain="?\*"?']},
            ],
        }],
    },
    {
        "id": "clientaccesspolicy-xml-exposure",
        "info": {"name": "Permissive clientaccesspolicy.xml (Silverlight CORS)", "severity": "medium",
                  "tags": "exposure,misconfig,cors"},
        "http": [{
            "method": "GET",
            "path": ["/clientaccesspolicy.xml"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["<cross-domain-access>", "uri=\"*\""]},
            ],
        }],
    },
    {
        "id": "robots-txt-admin-disclosure",
        "info": {"name": "robots.txt discloses sensitive admin/internal paths", "severity": "info",
                  "tags": "exposure,fingerprint,disclosure"},
        "http": [{
            "method": "GET",
            "path": ["/robots.txt"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r"(?i)Disallow:\s*/(admin|login|wp-admin|backend|api|private|internal|dashboard)"]},
            ],
            "extractors": [
                {"regex": [r"(?i)Disallow:\s*(/\S+)"]},
            ],
        }],
    },
    {
        "id": "security-txt-exposure",
        "info": {"name": "security.txt disclosure (may reveal contact / policy info)", "severity": "info",
                  "tags": "exposure,fingerprint,disclosure"},
        "http": [{
            "method": "GET",
            "path": ["/.well-known/security.txt", "/security.txt"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"Contact:\s*", r"Expires:\s*", r"Encryption:\s*"]},
            ],
        }],
    },
    {
        "id": "sitemap-xml-exposure",
        "info": {"name": "sitemap.xml exposed (URL enumeration aid)", "severity": "info",
                  "tags": "exposure,fingerprint,disclosure"},
        "http": [{
            "method": "GET",
            "path": ["/sitemap.xml", "/sitemap_index.xml", "/sitemap.xml.gz"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["<urlset", "<sitemapindex", "<sitemap>"]},
            ],
        }],
    },
    {
        "id": "exposed-log-files",
        "info": {"name": "Exposed application log file", "severity": "medium",
                  "tags": "exposure,log,misconfig"},
        "http": [{
            "method": "GET",
            "path": ["/logs/error.log", "/log/error.log", "/logs/app.log",
                     "/app.log", "/application.log", "/error.log", "/access.log"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}",
                           r"(?i)(error|exception|warning|fatal)\b",
                           r"(?i)(GET|POST)\s+/\S+\s+HTTP"]},
            ],
        }],
    },
    {
        "id": "exposed-sql-dump",
        "info": {"name": "Exposed SQL dump / database backup", "severity": "critical",
                  "tags": "exposure,database,backup,secrets"},
        "http": [{
            "method": "GET",
            "path": ["/dump.sql", "/db.sql", "/database.sql", "/backup.sql",
                     "/mysql.sql", "/data.sql", "/export.sql", "/full_backup.sql"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)INSERT INTO\s+`?\w+`?",
                           r"(?i)CREATE TABLE\s+`?\w+`?",
                           r"(?i)-- MySQL dump", r"(?i)-- PostgreSQL database dump"]},
            ],
        }],
    },
    {
        "id": "wpjson-user-enumeration",
        "info": {"name": "WordPress REST API user enumeration (/wp-json/wp/v2/users)", "severity": "medium",
                  "tags": "exposure,wordpress,api,fingerprint"},
        "http": [{
            "method": "GET",
            "path": ["/wp-json/wp/v2/users"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r'"id"\s*:\s*\d+', r'"name"\s*:']},
            ],
            "extractors": [
                {"regex": [r'"name"\s*:\s*"([^"]+)"']},
            ],
        }],
    },
    {
        "id": "git-info-refs-exposure",
        "info": {"name": "Exposed .git/info/refs (smart-HTTP pack protocol)", "severity": "high",
                  "tags": "exposure,git,vcs"},
        "http": [{
            "method": "GET",
            "path": ["/.git/info/refs?service=git-upload-pack"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r"[0-9a-f]{4}# service=git-upload-pack", r"[0-9a-f]{40}\s+refs/"]},
            ],
        }],
    },
    {
        "id": "database-connection-string-exposure",
        "info": {"name": "Database connection string in source / config", "severity": "critical",
                  "tags": "exposure,config,secrets,database"},
        "http": [{
            "method": "GET",
            "path": ["/config.php", "/config/database.php", "/config/db.php",
                     "/app/config/database.php", "/includes/config.php",
                     "/db_config.php", "/database.php"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)(mysqli_connect|PDO|mysql_connect|pg_connect)\s*\(",
                           r"(?i)(DB_HOST|DB_PASSWORD|DB_USER)\s*=",
                           r"(?i)(mysql|pgsql|sqlite)://\w+:\w+@"]},
            ],
        }],
    },
]


def filter_templates(templates, severities=None, tags=None):
    out = []
    for t in templates:
        info = t.get("info", {})
        if severities and info.get("severity", "info").lower() not in severities:
            continue
        if tags:
            tpl_tags = set(x.strip().lower() for x in str(info.get("tags", "")).split(","))
            if not (tpl_tags & tags):
                continue
        out.append(t)
    return out


# ------------------------------------------------------------------ #
# Matcher / extractor engine
# ------------------------------------------------------------------ #
def is_auth_cookie_name(name):
    lname = (name or "").strip().lower()
    if not lname:
        return False

    ignore_exact = {
        "_ga", "_gid", "_gat", "_fbp", "_gcl_au", "consent", "optanonconsent",
        "__cf_bm", "_hjsession", "_hjsessionuser", "_uetsid", "_uetvid", "_clck", "_clsk",
    }
    if lname in ignore_exact:
        return False

    auth_keywords = [
        "session", "sess", "sid", "token", "auth", "jwt", "remember", "csrf",
    ]

    if lname.startswith("__host-") or lname.startswith("__secure-"):
        return True

    return any(k in lname for k in auth_keywords)


def parse_set_cookie_headers(resp):
    raw_headers = []

    try:
        raw_headers = resp.raw.headers.getlist("Set-Cookie")
    except Exception:
        raw_headers = []

    if not raw_headers:
        try:
            for k, v in resp.headers.items():
                if k.lower() == "set-cookie":
                    raw_headers.append(v)
        except Exception:
            pass

    parsed = []
    for line in raw_headers:
        if not line:
            continue
        parts = [p.strip() for p in line.split(";") if p.strip()]
        if not parts or "=" not in parts[0]:
            continue
        name = parts[0].split("=", 1)[0].strip()
        attrs = set(p.split("=", 1)[0].strip().lower() for p in parts[1:])
        parsed.append({
            "name": name,
            "raw": line,
            "attrs": attrs,
            "is_auth": is_auth_cookie_name(name),
        })

    return parsed


def eval_matcher(m, resp, body_text):
    mtype = m.get("type")
    part = m.get("part", "body")
    if part == "header":
        target = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    else:
        target = body_text

    if mtype == "status":
        return resp.status_code in m.get("status", [])

    negative = m.get("negative", False)
    result = False

    if mtype == "word":
        words = m.get("words", [])
        cond = m.get("condition", "or")
        hits = [w in target for w in words]
        result = all(hits) if cond == "and" else any(hits)
    elif mtype == "regex":
        patterns = m.get("regex", [])
        cond = m.get("condition", "or")
        hits = [re.search(p, target, re.IGNORECASE) is not None for p in patterns]
        result = all(hits) if cond == "and" else any(hits)
    elif mtype == "header_absent":
        result = m.get("header", "").lower() not in [h.lower() for h in resp.headers.keys()]
    elif mtype == "cookie_flag_missing":
        flag = (m.get("flag") or "").strip().lower()
        if flag:
            cookies = parse_set_cookie_headers(resp)
            auth_cookies = [c for c in cookies if c.get("is_auth")]
            result = any(flag not in c.get("attrs", set()) for c in auth_cookies)

    return (not result) if negative else result


def run_extractors(extractors, body_text, resp=None):
    found = []
    for ex in extractors or []:
        for p in ex.get("regex", []):
            matches = re.findall(p, body_text)
            found.extend(matches if isinstance(matches, list) else [matches])

        if resp is not None:
            for flag in ex.get("cookie_flag_missing", []):
                flag_l = (flag or "").strip().lower()
                if not flag_l:
                    continue
                cookies = parse_set_cookie_headers(resp)
                for c in cookies:
                    if c.get("is_auth") and flag_l not in c.get("attrs", set()):
                        found.append(f"{c.get('name')} missing {flag}")

    return found[:10]


def matches_condition(results, condition):
    if not results:
        return False
    return all(results) if condition == "and" else any(results)


# ------------------------------------------------------------------ #
# HTTP request execution
# ------------------------------------------------------------------ #
def do_request(session, base_url, req, timeout):
    path = req.get("path", "/")
    method = req.get("method", "GET").upper()
    url = urljoin(base_url if base_url.endswith("/") else base_url + "/", path.lstrip("/"))
    headers = dict(req.get("headers", {}) or {})
    headers.setdefault("User-Agent", "kArmasnuc/2.0")
    body = req.get("body")
    try:
        resp = session.request(
            method, url, headers=headers, data=body,
            timeout=timeout, verify=False, allow_redirects=True,
        )
        return url, resp
    except requests.RequestException:
        return url, None


def scan_target(target, templates, timeout=8):
    session = requests.Session()
    findings = []
    if not target.startswith("http"):
        target = "http://" + target

    for tpl in templates:
        info = tpl.get("info", {})
        for block in tpl.get("http", []):
            paths = block.get("path", ["/"])
            if isinstance(paths, str):
                paths = [paths]
            matchers_cond = block.get("matchers-condition", "or")

            for path in paths:
                url, resp = do_request(session, target, {**block, "path": path}, timeout)
                if resp is None:
                    continue
                body_text = resp.text if resp.text else ""

                matcher_results = [eval_matcher(m, resp, body_text) for m in block.get("matchers", [])]
                if matches_condition(matcher_results, matchers_cond):
                    extracted = run_extractors(block.get("extractors"), body_text, resp)
                    findings.append({
                        "template": tpl.get("id"),
                        "name": info.get("name", tpl.get("id")),
                        "severity": info.get("severity", "info"),
                        "tags": info.get("tags", ""),
                        "matched_url": url,
                        "status_code": resp.status_code,
                        "extracted": extracted,
                    })
                    break  # one hit per template block is enough
    return target, findings


# ------------------------------------------------------------------ #
# Output
# ------------------------------------------------------------------ #
def print_finding(f):
    sev = f["severity"].lower()
    color = SEVERITY_COLOR.get(sev, RESET)
    tags = f"{GREY}[{f['tags']}]{RESET}" if f.get("tags") else ""
    print(f"{color}[{sev.upper():^8}]{RESET} {BOLD}{f['template']}{RESET} {tags}")
    print(f"    {GREEN}→{RESET} {f['matched_url']}  {GREY}({f['status_code']}){RESET}")
    if f.get("extracted"):
        print(f"    {CYAN}extracted:{RESET} {f['extracted']}")


def write_output(all_results, out_path):
    ext = os.path.splitext(out_path)[1].lower()
    if ext == ".json":
        with open(out_path, "w") as f:
            json.dump(all_results, f, indent=2)
    elif ext == ".csv":
        import csv
        with open(out_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["target", "template", "severity", "tags", "matched_url", "status_code", "extracted"])
            for target, findings in all_results.items():
                for f_ in findings:
                    w.writerow([target, f_["template"], f_["severity"], f_["tags"],
                                f_["matched_url"], f_["status_code"], ";".join(f_.get("extracted", []))])
    else:
        with open(out_path, "w") as f:
            for target, findings in all_results.items():
                for f_ in findings:
                    f.write(f"[{f_['severity'].upper()}] {f_['template']} -> {f_['matched_url']} ({f_['status_code']})\n")


def print_template_list(templates):
    print(f"{BOLD}{CYAN}{'ID':32} {'SEVERITY':10} TAGS{RESET}")
    for t in templates:
        info = t.get("info", {})
        sev = info.get("severity", "info").lower()
        color = SEVERITY_COLOR.get(sev, RESET)
        print(f"{t['id']:32} {color}{sev:10}{RESET} {info.get('tags', '')}")
    print(f"\n{GREY}{len(templates)} templates total{RESET}")


# ------------------------------------------------------------------ #
# Main
# ------------------------------------------------------------------ #
def main():
    ap = argparse.ArgumentParser(description="kArmasnuc — single-file template-based web detection scanner")
    ap.add_argument("-u", "--url", help="single target URL")
    ap.add_argument("-l", "--list", help="file of target URLs (one per line)")
    ap.add_argument("-c", "--concurrency", type=int, default=20, help="concurrent target workers")
    ap.add_argument("-timeout", type=int, default=8, help="per-request timeout (seconds)")
    ap.add_argument("-severity", help="comma-separated severities to include (info,low,medium,high,critical)")
    ap.add_argument("-tags", help="comma-separated tags to include")
    ap.add_argument("-o", "--output", help="output file (.json, .csv, or .txt)")
    ap.add_argument("-silent", action="store_true", help="suppress banner")
    ap.add_argument("-list-templates", action="store_true", help="list all embedded templates and exit")
    args = ap.parse_args()

    if not args.silent:
        print(BANNER)

    severities = set(s.strip().lower() for s in args.severity.split(",")) if args.severity else None
    tags = set(s.strip().lower() for s in args.tags.split(",")) if args.tags else None
    templates = filter_templates(TEMPLATES, severities, tags)

    if args.list_templates:
        print_template_list(templates)
        return

    if not args.url and not args.list:
        ap.error("provide -u/--url or -l/--list (or -list-templates)")

    targets = []
    if args.url:
        targets.append(args.url.strip())
    if args.list:
        with open(args.list) as f:
            targets.extend([line.strip() for line in f if line.strip()])

    if not templates:
        print(f"{RED}[!] no templates matched the given severity/tag filters{RESET}")
        sys.exit(1)

    print(f"{GREY}[*] {len(templates)} templates loaded | {len(targets)} target(s) | concurrency={args.concurrency}{RESET}\n")

    all_results = {}
    total_findings = 0
    start = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {pool.submit(scan_target, t, templates, args.timeout): t for t in targets}
        for fut in concurrent.futures.as_completed(futures):
            target, findings = fut.result()
            all_results[target] = findings
            if findings:
                print(f"{BOLD}{CYAN}== {target} =={RESET}")
                for f_ in findings:
                    print_finding(f_)
                    total_findings += 1
                print()

    elapsed = time.time() - start
    print(f"{GREY}[*] scan complete in {elapsed:.1f}s — {total_findings} finding(s) across {len(targets)} target(s){RESET}")

    if args.output:
        write_output(all_results, args.output)
        print(f"{GREEN}[+] results written to {args.output}{RESET}")


if __name__ == "__main__":
    main()
