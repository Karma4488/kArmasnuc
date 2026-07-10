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
    # Exposed config / backup / secret files
    # ------------------------------------------------------------------ #
    {
        "id": "dotenv-variants-exposure",
        "info": {"name": "Exposed .env variant files", "severity": "critical",
                  "tags": "exposure,config,secrets"},
        "http": [{
            "method": "GET",
            "path": ["/.env.prod", "/.env.production", "/.env.local", "/.env.development",
                     "/.env.dev", "/.env.staging", "/.env.test", "/.env.backup",
                     "/.env.example", "/.env.sample"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r"(?i)(DB_PASSWORD|APP_KEY|SECRET|API_KEY|PASSWORD|TOKEN|PASS)\s*="]},
            ],
        }],
    },
    {
        "id": "git-head-exposure",
        "info": {"name": "Exposed .git/HEAD file", "severity": "medium",
                  "tags": "exposure,git,vcs"},
        "http": [{
            "method": "GET",
            "path": ["/.git/HEAD"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r"^ref:\s+refs/heads/"]},
            ],
        }],
    },
    {
        "id": "svn-exposure",
        "info": {"name": "Exposed Subversion (.svn) metadata", "severity": "medium",
                  "tags": "exposure,svn,vcs"},
        "http": [{
            "method": "GET",
            "path": ["/.svn/entries", "/.svn/wc.db"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)SVN\b", r"(?i)dir\s+\d+\s+http", r"SQLite format"]},
            ],
        }],
    },
    {
        "id": "hgrc-exposure",
        "info": {"name": "Exposed Mercurial (.hg/hgrc) config", "severity": "medium",
                  "tags": "exposure,hg,vcs"},
        "http": [{
            "method": "GET",
            "path": ["/.hg/hgrc"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r"(?i)\[paths\]|\[ui\]|\[auth\]"]},
            ],
        }],
    },
    {
        "id": "gitignore-exposure",
        "info": {"name": "Exposed .gitignore (reveals project paths)", "severity": "info",
                  "tags": "exposure,git,vcs"},
        "http": [{
            "method": "GET",
            "path": ["/.gitignore"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)\.(env|log|key|pem|sql|bak|cfg|conf|ini|yml|yaml)\b",
                            r"(?m)^#\s*\S"]},
            ],
        }],
    },
    {
        "id": "htaccess-exposure",
        "info": {"name": "Exposed .htaccess file", "severity": "medium",
                  "tags": "exposure,apache,config"},
        "http": [{
            "method": "GET",
            "path": ["/.htaccess"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)RewriteRule|Deny from|Allow from|AuthType|Options\s+"]},
            ],
        }],
    },
    {
        "id": "composer-json-exposure",
        "info": {"name": "Exposed composer.json (PHP dependencies)", "severity": "low",
                  "tags": "exposure,php,config"},
        "http": [{
            "method": "GET",
            "path": ["/composer.json"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ['"require"', '"require-dev"', '"name"', '"version"']},
            ],
        }],
    },
    {
        "id": "package-json-exposure",
        "info": {"name": "Exposed package.json (Node.js dependencies)", "severity": "low",
                  "tags": "exposure,nodejs,config"},
        "http": [{
            "method": "GET",
            "path": ["/package.json"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ['"dependencies"', '"devDependencies"', '"scripts"', '"version"']},
            ],
        }],
    },
    {
        "id": "dockerfile-exposure",
        "info": {"name": "Exposed Dockerfile", "severity": "low",
                  "tags": "exposure,docker,config"},
        "http": [{
            "method": "GET",
            "path": ["/Dockerfile"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r"(?m)^FROM\s+\S+"]},
            ],
        }],
    },
    {
        "id": "docker-compose-exposure",
        "info": {"name": "Exposed docker-compose.yml", "severity": "medium",
                  "tags": "exposure,docker,config"},
        "http": [{
            "method": "GET",
            "path": ["/docker-compose.yml", "/docker-compose.yaml",
                     "/docker-compose.override.yml"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)services:", r"(?i)image:\s+\S+"]},
            ],
        }],
    },
    {
        "id": "npmrc-exposure",
        "info": {"name": "Exposed .npmrc (may contain auth tokens)", "severity": "high",
                  "tags": "exposure,nodejs,secrets"},
        "http": [{
            "method": "GET",
            "path": ["/.npmrc"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)registry\s*=", r"(?i)_authToken\s*=", r"(?i)//registry"]},
            ],
        }],
    },
    {
        "id": "application-yml-exposure",
        "info": {"name": "Exposed application.yml / application.yaml (Spring / app config)",
                  "severity": "high", "tags": "exposure,config,secrets,spring"},
        "http": [{
            "method": "GET",
            "path": ["/application.yml", "/application.yaml",
                     "/application-prod.yml", "/application-production.yml"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)datasource:", r"(?i)password:", r"(?i)secret:",
                            r"(?i)spring:", r"(?i)database:"]},
            ],
        }],
    },
    {
        "id": "database-yml-exposure",
        "info": {"name": "Exposed database.yml (Rails DB credentials)", "severity": "critical",
                  "tags": "exposure,rails,secrets,config"},
        "http": [{
            "method": "GET",
            "path": ["/database.yml", "/config/database.yml"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)adapter:\s+\S+", r"(?i)database:\s+\S+",
                            r"(?i)password:\s+\S"]},
            ],
        }],
    },
    {
        "id": "web-config-exposure",
        "info": {"name": "Exposed web.config with connection strings", "severity": "high",
                  "tags": "exposure,aspnet,secrets,config"},
        "http": [{
            "method": "GET",
            "path": ["/web.config"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)connectionString", r"(?i)appSettings"]},
            ],
        }],
    },
    {
        "id": "aws-credentials-exposure",
        "info": {"name": "Exposed AWS credentials file", "severity": "critical",
                  "tags": "exposure,cloud,aws,secrets"},
        "http": [{
            "method": "GET",
            "path": ["/.aws/credentials"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)aws_access_key_id\s*=", r"(?i)aws_secret_access_key\s*="]},
            ],
        }],
    },
    {
        "id": "terraform-tfstate-exposure",
        "info": {"name": "Exposed Terraform state file (terraform.tfstate)", "severity": "critical",
                  "tags": "exposure,cloud,terraform,secrets"},
        "http": [{
            "method": "GET",
            "path": ["/terraform.tfstate", "/terraform/terraform.tfstate",
                     "/infrastructure/terraform.tfstate"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"terraform_version"', r'"resources"\s*:', r'"outputs"\s*:']},
            ],
        }],
    },
    {
        "id": "terraform-tfvars-exposure",
        "info": {"name": "Exposed Terraform variables file (terraform.tfvars)", "severity": "high",
                  "tags": "exposure,cloud,terraform,secrets"},
        "http": [{
            "method": "GET",
            "path": ["/terraform.tfvars", "/variables.tfvars", "/.tfvars"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r'(?i)\w+\s*=\s*"[^"]*"']},
            ],
        }],
    },
    {
        "id": "kubeconfig-exposure",
        "info": {"name": "Exposed Kubernetes config file", "severity": "critical",
                  "tags": "exposure,cloud,kubernetes,secrets"},
        "http": [{
            "method": "GET",
            "path": ["/.kube/config", "/kubeconfig", "/kube-config"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)apiVersion:", r"(?i)clusters:", r"(?i)current-context:"]},
            ],
        }],
    },
    {
        "id": "service-account-json-exposure",
        "info": {"name": "Exposed GCP service account key (JSON)", "severity": "critical",
                  "tags": "exposure,cloud,gcp,secrets"},
        "http": [{
            "method": "GET",
            "path": ["/service-account.json", "/service_account.json",
                     "/credentials.json", "/gcp-key.json", "/sa-key.json"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"type"\s*:\s*"service_account"',
                            r'"private_key_id"', r'"client_email"']},
            ],
        }],
    },
    {
        "id": "private-key-exposure",
        "info": {"name": "Exposed private key or certificate file", "severity": "critical",
                  "tags": "exposure,tls,secrets"},
        "http": [{
            "method": "GET",
            "path": ["/server.key", "/server.pem", "/privkey.pem", "/private.key",
                     "/ssl.key", "/id_rsa", "/.ssh/id_rsa"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"]},
            ],
        }],
    },
    {
        "id": "web-inf-web-xml-exposure",
        "info": {"name": "Exposed Java WEB-INF/web.xml deployment descriptor", "severity": "high",
                  "tags": "exposure,java,config"},
        "http": [{
            "method": "GET",
            "path": ["/WEB-INF/web.xml"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)<web-app", r"(?i)<servlet>", r"(?i)<filter>"]},
            ],
        }],
    },
    {
        "id": "wsdl-exposure",
        "info": {"name": "Exposed WSDL (web service description)", "severity": "low",
                  "tags": "exposure,soap,api"},
        "http": [{
            "method": "GET",
            "path": ["/service?wsdl", "/services?wsdl", "/api?wsdl",
                     "/ws?wsdl", "/Service.asmx?wsdl"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)<wsdl:definitions", r"(?i)<definitions.*xmlns.*wsdl"]},
            ],
        }],
    },
    {
        "id": "readme-version-disclosure",
        "info": {"name": "README/CHANGELOG exposes version information", "severity": "info",
                  "tags": "disclosure,exposure"},
        "http": [{
            "method": "GET",
            "path": ["/README.md", "/CHANGELOG.md", "/CHANGES.md",
                     "/RELEASE_NOTES.md", "/VERSION"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?im)^#+ ", r"(?i)v\d+\.\d+\.\d+",
                            r"(?i)version\s+\d"]},
            ],
        }],
    },

    # ------------------------------------------------------------------ #
    # Debug / status / health endpoints
    # ------------------------------------------------------------------ #
    {
        "id": "spring-boot-actuator-exposure",
        "info": {"name": "Spring Boot Actuator endpoints exposed", "severity": "high",
                  "tags": "exposure,spring,actuator,debug"},
        "http": [{
            "method": "GET",
            "path": ["/actuator", "/actuator/env", "/actuator/beans",
                     "/actuator/mappings", "/actuator/info"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"_links"', r'"beans"', r'"activeProfiles"',
                            r'"applicationConfig"', r'"propertySources"']},
            ],
        }],
    },
    {
        "id": "spring-boot-heapdump",
        "info": {"name": "Spring Boot Actuator heapdump exposed", "severity": "critical",
                  "tags": "exposure,spring,actuator,secrets"},
        "http": [{
            "method": "GET",
            "path": ["/actuator/heapdump"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "header",
                 "regex": [r"(?i)Content-Type:\s*application/octet-stream"]},
            ],
        }],
    },
    {
        "id": "apache-server-status",
        "info": {"name": "Apache mod_status page exposed", "severity": "medium",
                  "tags": "exposure,apache,debug"},
        "http": [{
            "method": "GET",
            "path": ["/server-status", "/server-status?auto"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)Apache Server Status", r"(?i)ServerVersion:",
                            r"(?i)Total Accesses:"]},
            ],
        }],
    },
    {
        "id": "apache-server-info",
        "info": {"name": "Apache mod_info page exposed", "severity": "medium",
                  "tags": "exposure,apache,debug"},
        "http": [{
            "method": "GET",
            "path": ["/server-info"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)Apache HTTP Server Information",
                            r"(?i)Module Name.*Module Identifier"]},
            ],
        }],
    },
    {
        "id": "prometheus-metrics-exposed",
        "info": {"name": "Prometheus metrics endpoint exposed", "severity": "medium",
                  "tags": "exposure,prometheus,metrics,debug"},
        "http": [{
            "method": "GET",
            "path": ["/metrics", "/prometheus", "/prometheus/metrics"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?m)^# HELP ", r"(?m)^# TYPE "]},
            ],
        }],
    },
    {
        "id": "health-check-endpoints",
        "info": {"name": "Application health/status endpoint exposed", "severity": "info",
                  "tags": "exposure,debug,health"},
        "http": [{
            "method": "GET",
            "path": ["/health", "/healthz", "/health-check", "/healthcheck",
                     "/health/ready", "/health/live", "/_ah/health", "/ping"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'(?i)"status"\s*:\s*"(UP|OK|pass|healthy)',
                            r"(?i)\bstatus\s*:\s*(UP|OK)\b",
                            r"(?i)\bhealthy\b"]},
            ],
        }],
    },
    {
        "id": "rails-info-exposure",
        "info": {"name": "Rails info routes/properties endpoint exposed", "severity": "medium",
                  "tags": "exposure,rails,debug"},
        "http": [{
            "method": "GET",
            "path": ["/rails/info/properties", "/rails/info/routes"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)Rails\.version", r"(?i)Ruby version",
                            r"(?i)Application routes"]},
            ],
        }],
    },
    {
        "id": "xdebug-exposure",
        "info": {"name": "PHP Xdebug exposed (remote debug session)", "severity": "high",
                  "tags": "exposure,php,debug"},
        "http": [{
            "method": "GET",
            "path": ["/"],
            "headers": {"X-Forwarded-For": "169.254.169.254",
                        "Cookie": "XDEBUG_SESSION=PHPSTORM"},
            "matchers-condition": "or",
            "matchers": [
                {"type": "regex", "part": "header",
                 "regex": [r"(?i)X-Debug-Tag:", r"(?i)XDEBUG_SESSION"]},
                {"type": "regex", "part": "body",
                 "regex": [r"(?i)Xdebug.*Remote Debugging", r"(?i)xdebug\.remote_host"]},
            ],
        }],
    },
    {
        "id": "php-opcache-status",
        "info": {"name": "PHP OPcache status page exposed", "severity": "medium",
                  "tags": "exposure,php,debug"},
        "http": [{
            "method": "GET",
            "path": ["/opcache-status.php", "/opcache.php", "/opcache_status.php"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)opcache", r"(?i)OPcache\s+Status"]},
            ],
        }],
    },

    # ------------------------------------------------------------------ #
    # Framework / platform-specific disclosure artifacts
    # ------------------------------------------------------------------ #
    {
        "id": "symfony-profiler-exposure",
        "info": {"name": "Symfony debug profiler exposed", "severity": "high",
                  "tags": "exposure,symfony,debug,php"},
        "http": [{
            "method": "GET",
            "path": ["/_profiler/", "/_profiler/latest", "/_wdt/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)Symfony\s+Profiler", r"(?i)sf-toolbar",
                            r"(?i)_profiler"]},
            ],
        }],
    },
    {
        "id": "laravel-telescope-exposure",
        "info": {"name": "Laravel Telescope dashboard exposed", "severity": "high",
                  "tags": "exposure,laravel,debug,php"},
        "http": [{
            "method": "GET",
            "path": ["/telescope", "/telescope/requests"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)laravel\s+telescope", r"(?i)/telescope/",
                            r'"telescope"']},
            ],
        }],
    },
    {
        "id": "laravel-debugbar-exposure",
        "info": {"name": "Laravel Debugbar exposed", "severity": "medium",
                  "tags": "exposure,laravel,debug,php"},
        "http": [{
            "method": "GET",
            "path": ["/_debugbar/open"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)debugbar", r'"PhpDebugBar"']},
            ],
        }],
    },
    {
        "id": "aspnet-trace-exposure",
        "info": {"name": "ASP.NET trace viewer (trace.axd) exposed", "severity": "high",
                  "tags": "exposure,aspnet,debug"},
        "http": [{
            "method": "GET",
            "path": ["/trace.axd"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)Application\s+Trace", r"(?i)ASP\.NET.*Trace",
                            r"(?i)trace\.axd"]},
            ],
        }],
    },
    {
        "id": "aspnet-elmah-exposure",
        "info": {"name": "ASP.NET ELMAH error log (elmah.axd) exposed", "severity": "high",
                  "tags": "exposure,aspnet,debug,errors"},
        "http": [{
            "method": "GET",
            "path": ["/elmah.axd", "/elmah/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)Error Log for", r"(?i)ELMAH",
                            r"(?i)Application Error Log"]},
            ],
        }],
    },
    {
        "id": "wp-json-users-disclosure",
        "info": {"name": "WordPress REST API user enumeration (/wp-json/wp/v2/users)",
                  "severity": "medium", "tags": "exposure,wordpress,api"},
        "http": [{
            "method": "GET",
            "path": ["/wp-json/wp/v2/users"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"slug"\s*:', r'"name"\s*:\s*"', r'"id"\s*:\s*\d+']},
            ],
            "extractors": [
                {"regex": [r'"slug"\s*:\s*"([^"]+)"']},
            ],
        }],
    },
    {
        "id": "drupal-install-exposure",
        "info": {"name": "Drupal install.php accessible", "severity": "medium",
                  "tags": "exposure,drupal,cms,setup"},
        "http": [{
            "method": "GET",
            "path": ["/core/install.php", "/install.php"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)Drupal\s+installation", r"(?i)Choose\s+language",
                            r"(?i)drupal\.org"]},
            ],
        }],
    },
    {
        "id": "crossdomain-xml-permissive",
        "info": {"name": "Permissive crossdomain.xml (allow-access-from domain=*)",
                  "severity": "medium", "tags": "misconfig,cors,flash"},
        "http": [{
            "method": "GET",
            "path": ["/crossdomain.xml"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r'(?i)allow-access-from\s+domain\s*=\s*["\']?\*']},
            ],
        }],
    },

    # ------------------------------------------------------------------ #
    # API docs / schema exposure
    # ------------------------------------------------------------------ #
    {
        "id": "swagger-ui-exposure",
        "info": {"name": "Swagger UI API documentation exposed", "severity": "medium",
                  "tags": "exposure,api,swagger"},
        "http": [{
            "method": "GET",
            "path": ["/swagger-ui.html", "/swagger-ui/", "/swagger-ui/index.html",
                     "/swagger/", "/api/swagger-ui.html"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)swagger-ui", r"(?i)Swagger\s+UI",
                            r"(?i)SwaggerUIBundle"]},
            ],
        }],
    },
    {
        "id": "openapi-schema-exposure",
        "info": {"name": "OpenAPI / Swagger JSON schema exposed", "severity": "medium",
                  "tags": "exposure,api,openapi,swagger"},
        "http": [{
            "method": "GET",
            "path": ["/openapi.json", "/openapi.yaml", "/api-docs",
                     "/v2/api-docs", "/v3/api-docs", "/api/swagger.json",
                     "/swagger.json"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"openapi"\s*:', r'"swagger"\s*:\s*"2\.',
                            r'"info"\s*:.*"title"', r"openapi:\s+['\"]?3\."]},
            ],
        }],
    },
    {
        "id": "graphql-introspection",
        "info": {"name": "GraphQL introspection enabled", "severity": "medium",
                  "tags": "exposure,api,graphql"},
        "http": [{
            "method": "GET",
            "path": ["/graphql?query={__schema{types{name}}}",
                     "/api/graphql?query={__schema{types{name}}}",
                     "/graphql/console"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"__schema"', r'"types"\s*:\s*\[', r"GraphiQL"]},
            ],
        }],
    },

    # ------------------------------------------------------------------ #
    # Admin / setup / install leftovers
    # ------------------------------------------------------------------ #
    {
        "id": "phpmyadmin-panel-exposure",
        "info": {"name": "phpMyAdmin panel exposed", "severity": "high",
                  "tags": "exposure,phpmyadmin,database,panel"},
        "http": [{
            "method": "GET",
            "path": ["/phpMyAdmin/", "/phpmyadmin/", "/pma/", "/mysql/",
                     "/phpMyAdmin/index.php"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)phpMyAdmin", r"(?i)pma_",
                            r"(?i)Welcome to phpMyAdmin"]},
            ],
        }],
    },
    {
        "id": "adminer-panel-exposure",
        "info": {"name": "Adminer database management panel exposed", "severity": "high",
                  "tags": "exposure,adminer,database,panel"},
        "http": [{
            "method": "GET",
            "path": ["/adminer.php", "/adminer/", "/adminer/adminer.php",
                     "/db/adminer.php"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)>Adminer<", r"(?i)adminer\.org",
                            r"(?i)Login\s*-\s*Adminer"]},
            ],
        }],
    },
    {
        "id": "setup-install-pages",
        "info": {"name": "Setup / install script accessible", "severity": "high",
                  "tags": "exposure,setup,misconfig"},
        "http": [{
            "method": "GET",
            "path": ["/setup.php", "/install.php", "/installer.php",
                     "/setup/", "/install/", "/installation/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)installation wizard", r"(?i)setup wizard",
                            r"(?i)database configuration", r"(?i)install step"]},
            ],
        }],
    },
    {
        "id": "tomcat-manager-exposure",
        "info": {"name": "Apache Tomcat manager panel exposed", "severity": "high",
                  "tags": "exposure,tomcat,panel,java"},
        "http": [{
            "method": "GET",
            "path": ["/manager/html", "/manager/status", "/host-manager/html"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200, 401, 403]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)Tomcat\s+(Web Application Manager|Manager)",
                            r"(?i)Apache\s+Tomcat"]},
            ],
        }],
    },
    {
        "id": "jenkins-dashboard-exposure",
        "info": {"name": "Jenkins dashboard or API exposed", "severity": "high",
                  "tags": "exposure,jenkins,ci,panel"},
        "http": [{
            "method": "GET",
            "path": ["/jenkins/", "/jenkins/api/json", "/api/json"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)Dashboard\s*\[Jenkins\]", r'"_class"\s*:\s*"hudson',
                            r'"jobs"\s*:\s*\[']},
            ],
        }],
    },
    {
        "id": "wordpress-install-exposure",
        "info": {"name": "WordPress installation page accessible", "severity": "medium",
                  "tags": "exposure,wordpress,setup,cms"},
        "http": [{
            "method": "GET",
            "path": ["/wp-admin/setup-config.php", "/wp-admin/install.php"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)WordPress.*installation", r"(?i)Let's install WordPress",
                            r"(?i)wp-admin/install"]},
            ],
        }],
    },

    # ------------------------------------------------------------------ #
    # Service panels / dashboards
    # ------------------------------------------------------------------ #
    {
        "id": "kibana-panel-exposure",
        "info": {"name": "Kibana dashboard exposed", "severity": "high",
                  "tags": "exposure,kibana,elasticsearch,panel"},
        "http": [{
            "method": "GET",
            "path": ["/app/kibana", "/kibana/", "/_cat/indices"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)kibana", r"(?i)kbn-", r"green\s+open\s+\S"]},
            ],
        }],
    },
    {
        "id": "elasticsearch-open",
        "info": {"name": "Elasticsearch cluster accessible without auth", "severity": "critical",
                  "tags": "exposure,elasticsearch,database"},
        "http": [{
            "method": "GET",
            "path": ["/_cluster/health", "/_nodes", "/_cat/indices?v"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"cluster_name"\s*:', r'"number_of_nodes"\s*:',
                            r'"status"\s*:\s*"(green|yellow|red)"']},
            ],
        }],
    },
    {
        "id": "grafana-panel-exposure",
        "info": {"name": "Grafana dashboard login page exposed", "severity": "medium",
                  "tags": "exposure,grafana,monitoring,panel"},
        "http": [{
            "method": "GET",
            "path": ["/grafana/", "/grafana/login", "/grafana/api/health"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)grafana", r'"database"\s*:\s*"ok"',
                            r"(?i)Grafana\s+v\d"]},
            ],
        }],
    },
    {
        "id": "jupyter-notebook-exposure",
        "info": {"name": "Jupyter Notebook interface exposed", "severity": "critical",
                  "tags": "exposure,jupyter,panel"},
        "http": [{
            "method": "GET",
            "path": ["/tree", "/notebooks/", "/api/kernels", "/jupyter/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)Jupyter\s+Notebook", r"(?i)IPython\s+Notebook",
                            r'"kernel_id"']},
            ],
        }],
    },
    {
        "id": "portainer-panel-exposure",
        "info": {"name": "Portainer Docker management UI exposed", "severity": "high",
                  "tags": "exposure,portainer,docker,panel"},
        "http": [{
            "method": "GET",
            "path": ["/portainer/", "/#/init/admin", "/api/system/status"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)portainer", r'"Version"\s*:\s*"',
                            r'"Swarm"\s*:']},
            ],
        }],
    },
    {
        "id": "solr-admin-exposure",
        "info": {"name": "Apache Solr admin panel exposed", "severity": "high",
                  "tags": "exposure,solr,database,panel"},
        "http": [{
            "method": "GET",
            "path": ["/solr/", "/solr/#/", "/solr/admin/info/system?wt=json"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)Solr\s+Admin", r'"solr-spec-version"',
                            r'"solr_home"\s*:']},
            ],
        }],
    },
    {
        "id": "rabbitmq-management-exposure",
        "info": {"name": "RabbitMQ management panel exposed", "severity": "high",
                  "tags": "exposure,rabbitmq,panel"},
        "http": [{
            "method": "GET",
            "path": ["/rabbitmq/", "/#/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)RabbitMQ\s+Management",
                            r"(?i)rabbitmq_management"]},
            ],
        }],
    },

    # ------------------------------------------------------------------ #
    # Missing security headers
    # ------------------------------------------------------------------ #
    {
        "id": "missing-content-security-policy",
        "info": {"name": "Missing Content-Security-Policy header", "severity": "low",
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
        "info": {"name": "Missing Referrer-Policy header", "severity": "info",
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
