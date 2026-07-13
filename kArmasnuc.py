#!/usr/bin/env python3
"""
kArmasnuc — template-driven web detection scanner (Nuclei-inspired)
Part of the kArmas suite. Single-file build — no external template files,
no YAML dependency. Everything (engine + templates) lives in this script.

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

SOFT_404_BODY_PATTERNS = [
    r"(?i)<title>\s*(404|not found|error|access denied|forbidden)",
    r"(?i)\b(404|page not found|not found|access denied|forbidden)\b",
    r"(?i)the requested url was not found",
    r"(?i)cannot (get|post) /",
]

TEXT_LIKE_CONTENT_TYPES = (
    "text/",
    "application/json",
    "application/javascript",
    "application/x-javascript",
    "application/xml",
    "application/xhtml+xml",
    "application/x-httpd-php",
    "application/x-sh",
    "application/x-yaml",
    "application/yaml",
)

# ------------------------------------------------------------------ #
# Embedded templates
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
            "path": ["/.env", "/.env.local", "/.env.production", "/.env.development",
                     "/.env.bak", "/.env.backup", "/.env.old"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r"(?i)(DB_PASSWORD|APP_KEY|SECRET_KEY|API_KEY|AWS_ACCESS_KEY_ID|DATABASE_URL|REDIS_URL|MAIL_PASSWORD|PRIVATE_KEY)\s*="]},
            ],
            "extractors": [
                {"regex": [r"(?i)([A-Z0-9_]+(?:_KEY|_TOKEN|_SECRET)|DB_PASSWORD|SECRET_KEY|DATABASE_URL)\s*=\s*(\S+)"]},
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
                     "/wp-config.php.bak", "/config.php.bak", "/config.bak",
                     "/backup.tgz", "/backup.tar", "/.htpasswd"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "header", "condition": "or",
                 "regex": [r"(?i)Content-Disposition:\s*attachment",
                          r"(?i)Content-Type:\s*(application/(zip|x-zip-compressed|gzip|x-gzip|x-tar|octet-stream)|text/plain|application/sql)"]},
                {"type": "regex", "part": "body", "negative": True,
                 "regex": [r"(?i)<title>\s*(404|not found|error)", r"(?i)<h1>\s*(404|not found|error)"]},
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
                 "words": ["wp-content", "wp-includes", "wp-login.php", "wp-json"]},
                {"type": "regex", "part": "header",
                 "regex": [r"(?im)^X-Pingback:\s*[^\r\n]*xmlrpc\.php", r"(?im)^Link:\s*<[^>]*wp-json[^>]*>"]},
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
    {
        "id": "git-head-exposure",
        "info": {"name": "Exposed .git/HEAD file", "severity": "high", "tags": "exposure,git,vcs"},
        "http": [{
            "method": "GET",
            "path": ["/.git/HEAD"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "regex": [r"ref:\s*refs/heads/"]},
            ],
        }],
    },
    {
        "id": "git-commit-editmsg-exposure",
        "info": {"name": "Exposed .git/COMMIT_EDITMSG", "severity": "medium", "tags": "exposure,git,vcs"},
        "http": [{
            "method": "GET",
            "path": ["/.git/COMMIT_EDITMSG"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "header", "regex": [r"(?i)Content-Type:\s*text/plain"]},
            ],
        }],
    },
    {
        "id": "git-logs-exposure",
        "info": {"name": "Exposed .git/logs/HEAD", "severity": "medium", "tags": "exposure,git,vcs"},
        "http": [{
            "method": "GET",
            "path": ["/.git/logs/HEAD"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "regex": [r"[0-9a-f]{40}"]},
            ],
        }],
    },
    {
        "id": "gitignore-exposure",
        "info": {"name": "Exposed .gitignore (path disclosure)", "severity": "low", "tags": "exposure,git,vcs"},
        "http": [{
            "method": "GET",
            "path": ["/.gitignore"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?m)^\s*[#*!]", r"(?m)^\s*\*\.\w+", r"(?m)^/?[\w./-]+(\.[\w]+)?$"]},
            ],
        }],
    },
    {
        "id": "gitmodules-exposure",
        "info": {"name": "Exposed .gitmodules (submodule path/URL disclosure)", "severity": "low", "tags": "exposure,git,vcs"},
        "http": [{
            "method": "GET",
            "path": ["/.gitmodules"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "words": ["[submodule"]},
            ],
        }],
    },
    {
        "id": "svn-entries-exposure",
        "info": {"name": "Exposed Subversion metadata", "severity": "high", "tags": "exposure,svn,config"},
        "http": [{
            "method": "GET",
            "path": ["/.svn/entries", "/.svn/wc.db"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?m)^dir\s*$", r"(?m)^\d+\s*$", r"(?m)^svn:.*$"]},
            ],
        }],
    },
    {
        "id": "mercurial-repo-exposure",
        "info": {"name": "Exposed Mercurial repository metadata", "severity": "high", "tags": "exposure,hg,config"},
        "http": [{
            "method": "GET",
            "path": ["/.hg/requires", "/.hg/hgrc"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["revlogv1", "store", "fncache", "[paths]"]},
            ],
        }],
    },
    {
        "id": "config-json-exposure",
        "info": {"name": "Exposed config.json with potential secrets", "severity": "high", "tags": "exposure,config,secrets"},
        "http": [{
            "method": "GET",
            "path": ["/app/config.json", "/config/config.json", "/assets/config.json",
                     "/static/config.json", "/public/config.json", "/dist/config.json",
                     "/build/config.json"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [
                     r"""(?i)['\"]?api[_-]?key['\"]?\s*:\s*['\"](?!test|xxxx|changeme|sample|demo)[^'\"]{8,}['\"]""",
                     r"""(?i)['\"]?client[_-]?secret['\"]?\s*:\s*['\"](?!test|xxxx|changeme|sample|demo)[^'\"]{8,}['\"]""",
                     r"""(?i)['\"]?jwt[_-]?secret['\"]?\s*:\s*['\"](?!test|xxxx|changeme|sample|demo)[^'\"]{8,}['\"]""",
                     r"""(?i)['\"]?db[_-]?password['\"]?\s*:\s*['\"](?!test|xxxx|changeme|sample|demo)[^'\"]{8,}['\"]""",
                     r"""(?i)['\"]?access[_-]?key[_-]?id['\"]?\s*:\s*['\"](?!test|xxxx|changeme|sample|demo)[^'\"]{8,}['\"]""",
                 ]},
            ],
        }],
    },
    {
        "id": "composer-files-exposure",
        "info": {"name": "Exposed Composer manifest / lock file", "severity": "medium", "tags": "exposure,php,composer"},
        "http": [{
            "method": "GET",
            "path": ["/composer.json", "/composer.lock"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"require"\s*:', r'"packages"\s*:']},
            ],
        }],
    },
    {
        "id": "docker-files-exposure",
        "info": {"name": "Exposed Docker build / compose file", "severity": "medium", "tags": "exposure,docker,config"},
        "http": [{
            "method": "GET",
            "path": ["/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?m)^FROM\s+\S+", r"(?m)^services:\s*$", r"(?m)^version:\s*[\"']?\d"]},
            ],
        }],
    },
    {
        "id": "db-admin-panels-detect",
        "info": {"name": "Database admin panel detected", "severity": "medium", "tags": "panel,admin,phpmyadmin,adminer,pgadmin"},
        "http": [{
            "method": "GET",
            "path": ["/phpmyadmin/", "/phpMyAdmin/", "/pma/", "/adminer.php", "/adminer/", "/pgadmin/", "/pgadmin4/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200, 401, 403]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["phpMyAdmin", "Adminer", "pgAdmin 4", "pgAdmin", "pmahomme"]},
            ],
        }],
    },
    {
        "id": "jenkins-panel-detect",
        "info": {"name": "Jenkins panel detected", "severity": "medium", "tags": "panel,admin,jenkins"},
        "http": [{
            "method": "GET",
            "path": ["/jenkins/", "/jenkins/login"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200, 401, 403]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["Jenkins", "Dashboard [Jenkins]", "Sign in [Jenkins]"]},
            ],
        }],
    },
    {
        "id": "observability-panels-detect",
        "info": {"name": "Grafana or Kibana panel detected", "severity": "medium", "tags": "panel,admin,grafana,kibana"},
        "http": [{
            "method": "GET",
            "path": ["/grafana/login", "/kibana/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["Grafana", "Welcome to Grafana", "kibanaWelcomeText", "Kibana"]},
            ],
        }],
    },
    {
        "id": "elasticsearch-open-instance",
        "info": {"name": "Elasticsearch open instance detected", "severity": "high", "tags": "exposure,elasticsearch,panel"},
        "http": [{
            "method": "GET",
            "path": ["/_cluster/health"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"cluster_name"\s*:', r'"status"\s*:\s*"(green|yellow|red)"']},
            ],
        }],
    },
    {
        "id": "swagger-ui-detect",
        "info": {"name": "Swagger UI / OpenAPI docs detected", "severity": "medium", "tags": "docs,api,swagger,openapi"},
        "http": [{
            "method": "GET",
            "path": ["/swagger-ui.html", "/swagger/index.html", "/swagger.json", "/v2/api-docs", "/v3/api-docs"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["Swagger UI", "\"swagger\":", "\"openapi\":"]},
            ],
        }],
    },
    {
        "id": "graphql-endpoint-detect",
        "info": {"name": "GraphQL endpoint detected", "severity": "medium", "tags": "api,graphql,debug"},
        "http": [{
            "method": "GET",
            "path": ["/graphql", "/graphql/", "/api/graphql", "/api/v1/graphql"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200, 400]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["GraphQL", "graphiql", "Must provide query string", "IntrospectionQuery"]},
            ],
        }],
    },
    {
        "id": "spring-actuator-exposure",
        "info": {"name": "Spring Boot Actuator endpoint exposed", "severity": "medium", "tags": "debug,spring,actuator"},
        "http": [{
            "method": "GET",
            "path": ["/actuator/health", "/actuator/env"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"status"\s*:\s*"(UP|DOWN|OUT_OF_SERVICE|UNKNOWN)"', r'"activeProfiles"\s*:', r'"propertySources"\s*:']},
            ],
        }],
    },
    {
        "id": "sensitive-ssh-files-exposure",
        "info": {"name": "Exposed SSH key or SSH config file", "severity": "critical", "tags": "exposure,ssh,secrets"},
        "http": [{
            "method": "GET",
            "path": ["/.ssh/id_rsa", "/.ssh/id_rsa.pub", "/.ssh/config"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"-----BEGIN (OPENSSH|RSA|DSA|EC) PRIVATE KEY-----",
                           r"(?m)^ssh-(rsa|ed25519|ecdsa)\s+[A-Za-z0-9+/=]+",
                           r"(?m)^\s*Host\s+\S+",
                           r"(?m)^\s*IdentityFile\s+\S+",
                           r"(?m)^\s*StrictHostKeyChecking\s+\S+",
                           r"(?m)^\s*ProxyCommand\s+\S+",
                           r"(?m)^\s*User\s+\S+",
                           r"(?m)^\s*Port\s+\d+"]},
            ],
        }],
    },
    {
        "id": "robots-txt-discovery",
        "info": {"name": "robots.txt discovered", "severity": "info", "tags": "osint,recon,robots,discovery"},
        "http": [{
            "method": "GET",
            "path": ["/robots.txt"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?im)^(User-agent|Disallow|Allow|Sitemap)\s*:"]},
            ],
        }],
    },
    {
        "id": "sitemap-xml-discovery",
        "info": {"name": "Sitemap XML discovered", "severity": "info", "tags": "osint,recon,sitemap,discovery"},
        "http": [{
            "method": "GET",
            "path": ["/sitemap.xml", "/sitemap_index.xml"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)<urlset\b", r"(?i)<sitemapindex\b", r"(?i)<loc>https?://"]},
            ],
        }],
    },
    {
        "id": "humans-txt-discovery",
        "info": {"name": "humans.txt discovered", "severity": "info", "tags": "osint,recon,humans,metadata"},
        "http": [{
            "method": "GET",
            "path": ["/humans.txt"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)TEAM", r"(?i)THANKS", r"(?i)HUMANS\.TXT"]},
            ],
        }],
    },
    {
        "id": "security-txt-discovery",
        "info": {"name": "security.txt discovered", "severity": "low", "tags": "osint,recon,security-txt,contact"},
        "http": [{
            "method": "GET",
            "path": ["/.well-known/security.txt", "/security.txt"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?im)^(Contact|Expires|Encryption|Policy|Acknowledgments)\s*:"]},
            ],
            "extractors": [
                {"regex": [r"(?im)^Contact:\s*(.+)$"]},
            ],
        }],
    },
    {
        "id": "ads-txt-discovery",
        "info": {"name": "ads.txt discovered", "severity": "info", "tags": "osint,recon,ads,metadata"},
        "http": [{
            "method": "GET",
            "path": ["/ads.txt"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?im)^[\w.-]+\s*,\s*\d+\s*,\s*(DIRECT|RESELLER)"]},
            ],
        }],
    },
    {
        "id": "assetlinks-json-discovery",
        "info": {"name": "Android assetlinks discovered", "severity": "info", "tags": "osint,recon,mobile,android,well-known"},
        "http": [{
            "method": "GET",
            "path": ["/.well-known/assetlinks.json"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"relation"\s*:', r'"target"\s*:', r'"android_app"']},
            ],
        }],
    },
    {
        "id": "apple-app-site-association-discovery",
        "info": {"name": "Apple app site association discovered", "severity": "info", "tags": "osint,recon,mobile,ios,well-known"},
        "http": [{
            "method": "GET",
            "path": ["/.well-known/apple-app-site-association", "/apple-app-site-association"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"applinks"\s*:', r'"webcredentials"\s*:', r'"appID"\s*:']},
            ],
        }],
    },
    {
        "id": "openid-configuration-discovery",
        "info": {"name": "OpenID configuration metadata discovered", "severity": "low", "tags": "osint,recon,openid,oauth,api,well-known"},
        "http": [{
            "method": "GET",
            "path": ["/.well-known/openid-configuration"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"issuer"\s*:', r'"authorization_endpoint"\s*:', r'"token_endpoint"\s*:']},
            ],
        }],
    },
    {
        "id": "oauth-authorization-server-discovery",
        "info": {"name": "OAuth authorization server metadata discovered", "severity": "low", "tags": "osint,recon,oauth,api,well-known"},
        "http": [{
            "method": "GET",
            "path": ["/.well-known/oauth-authorization-server"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"issuer"\s*:', r'"authorization_endpoint"\s*:', r'"jwks_uri"\s*:']},
            ],
        }],
    },
    {
        "id": "jwks-json-discovery",
        "info": {"name": "JWKS endpoint discovered", "severity": "low", "tags": "osint,recon,jwks,oauth,api"},
        "http": [{
            "method": "GET",
            "path": ["/.well-known/jwks.json", "/jwks.json"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"keys"\s*:\s*\[', r'"kty"\s*:', r'"kid"\s*:']},
            ],
        }],
    },
    {
        "id": "web-manifest-discovery",
        "info": {"name": "Web app manifest discovered", "severity": "info", "tags": "osint,recon,manifest,pwa,metadata"},
        "http": [{
            "method": "GET",
            "path": ["/manifest.json", "/site.webmanifest"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"name"\s*:', r'"short_name"\s*:', r'"start_url"\s*:']},
            ],
        }],
    },
    {
        "id": "browserconfig-xml-discovery",
        "info": {"name": "browserconfig.xml discovered", "severity": "info", "tags": "osint,recon,metadata,windows"},
        "http": [{
            "method": "GET",
            "path": ["/browserconfig.xml"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)<browserconfig\b", r"(?i)<msapplication\b", r"(?i)<tile"]},
            ],
        }],
    },
    {
        "id": "package-lock-exposure",
        "info": {"name": "Public package-lock metadata", "severity": "info", "tags": "osint,recon,metadata,nodejs"},
        "http": [{
            "method": "GET",
            "path": ["/package-lock.json"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"lockfileVersion"\s*:', r'"packages"\s*:', r'"dependencies"\s*:']},
            ],
        }],
    },
    {
        "id": "pnpm-lock-exposure",
        "info": {"name": "Public pnpm lock metadata", "severity": "info", "tags": "osint,recon,metadata,nodejs"},
        "http": [{
            "method": "GET",
            "path": ["/pnpm-lock.yaml"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?m)^lockfileVersion:\s*", r"(?m)^packages:\s*"]},
            ],
        }],
    },
    {
        "id": "readme-public-discovery",
        "info": {"name": "Public README discovered", "severity": "info", "tags": "osint,recon,docs,metadata"},
        "http": [{
            "method": "GET",
            "path": ["/README.md", "/readme.md", "/README.txt"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?im)^#\s+\w+", r"(?im)^##\s+\w+", r"(?i)(installation|usage|license)"]},
            ],
        }],
    },
    {
        "id": "changelog-public-discovery",
        "info": {"name": "Public changelog discovered", "severity": "info", "tags": "osint,recon,docs,changelog,versioning"},
        "http": [{
            "method": "GET",
            "path": ["/CHANGELOG.md", "/changelog.md", "/CHANGES.md"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)changelog", r"(?im)^##\s*\[?\d+\.\d+", r"(?i)(added|fixed|changed)"]},
            ],
        }],
    },
    {
        "id": "license-public-discovery",
        "info": {"name": "Public license file discovered", "severity": "info", "tags": "osint,recon,docs,license"},
        "http": [{
            "method": "GET",
            "path": ["/LICENSE", "/LICENSE.txt", "/LICENSE.md"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)MIT License", r"(?i)Apache License", r"(?i)GNU GENERAL PUBLIC LICENSE"]},
            ],
        }],
    },
    {
        "id": "gitignore-public-discovery",
        "info": {"name": "Public .gitignore discovered", "severity": "info", "tags": "osint,recon,dev,metadata"},
        "http": [{
            "method": "GET",
            "path": ["/.gitignore"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?m)^node_modules/?$", r"(?m)^\.env$", r"(?m)^__pycache__/"]},
            ],
        }],
    },
    {
        "id": "editorconfig-public-discovery",
        "info": {"name": "Public .editorconfig discovered", "severity": "info", "tags": "osint,recon,dev,metadata"},
        "http": [{
            "method": "GET",
            "path": ["/.editorconfig"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?m)^\[\*\]$", r"(?m)^indent_style\s*=", r"(?m)^end_of_line\s*="]},
            ],
        }],
    },
    {
        "id": "env-example-public-discovery",
        "info": {"name": "Public .env example file discovered", "severity": "low", "tags": "osint,recon,config,env,metadata"},
        "http": [{
            "method": "GET",
            "path": ["/.env.example", "/.env.sample", "/.env.dist", "/example.env"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?im)^(APP_ENV|APP_NAME|DATABASE_URL|DB_HOST)\s*="]},
            ],
        }],
    },
    {
        "id": "dockerignore-public-discovery",
        "info": {"name": "Public .dockerignore discovered", "severity": "info", "tags": "osint,recon,docker,metadata"},
        "http": [{
            "method": "GET",
            "path": ["/.dockerignore"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?m)^node_modules/?$", r"(?m)^\.git/?$", r"(?m)^Dockerfile$"]},
            ],
        }],
    },
    {
        "id": "requirements-txt-discovery",
        "info": {"name": "Public requirements.txt metadata", "severity": "info", "tags": "osint,recon,python,metadata"},
        "http": [{
            "method": "GET",
            "path": ["/requirements.txt"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?m)^[a-zA-Z0-9_.-]+(==|>=)\d[\w.:-]*"]},
            ],
        }],
    },
    {
        "id": "pyproject-toml-discovery",
        "info": {"name": "Public pyproject.toml metadata", "severity": "info", "tags": "osint,recon,python,metadata"},
        "http": [{
            "method": "GET",
            "path": ["/pyproject.toml"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?m)^\[build-system\]", r"(?m)^\[project\]", r"(?m)^name\s*="]},
            ],
        }],
    },
    {
        "id": "status-endpoint-metadata",
        "info": {"name": "Status endpoint metadata discovered", "severity": "low", "tags": "osint,recon,status,monitoring"},
        "http": [{
            "method": "GET",
            "path": ["/status", "/status.json", "/api/status"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'(?i)"status"\s*:\s*"(ok|up|healthy|degraded)"',
                           r'(?i)"uptime"\s*:\s*[\d.]+',
                           r'(?i)"version"\s*:\s*"[^"]+"']},
            ],
        }],
    },
    {
        "id": "health-endpoint-metadata",
        "info": {"name": "Health endpoint metadata discovered", "severity": "low", "tags": "osint,recon,health,monitoring"},
        "http": [{
            "method": "GET",
            "path": ["/health", "/healthz", "/livez", "/readyz"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)\b(healthy|ok|pass)\b", r'(?i)\"status\"\s*:']},
            ],
        }],
    },
    {
        "id": "prometheus-metrics-discovery",
        "info": {"name": "Prometheus metrics endpoint discovered", "severity": "low", "tags": "osint,recon,metrics,prometheus"},
        "http": [{
            "method": "GET",
            "path": ["/metrics", "/actuator/prometheus"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?m)^#\s*HELP\s+\w+", r"(?m)^#\s*TYPE\s+\w+", r"(?m)^process_cpu_seconds_total"]},
            ],
        }],
    },
    {
        "id": "javascript-sourcemap-exposure",
        "info": {"name": "JavaScript source map exposure", "severity": "low", "tags": "osint,recon,javascript,sourcemap"},
        "http": [{
            "method": "GET",
            "path": ["/app.js.map", "/main.js.map", "/bundle.js.map", "/static/js/main.js.map"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"version"\s*:\s*3', r'"sources"\s*:\s*\[', r'"mappings"\s*:']},
            ],
        }],
    },
    {
        "id": "public-email-disclosure",
        "info": {"name": "Public contact email disclosure", "severity": "info", "tags": "osint,recon,contact,email"},
        "http": [{
            "method": "GET",
            "path": ["/", "/contact", "/about", "/impressum"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)(?:mailto:)?[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"]},
            ],
            "extractors": [
                {"regex": [r"(?i)(?:mailto:)?[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"]},
            ],
        }],
    },
    {
        "id": "missing-browser-hardening-headers",
        "info": {"name": "Missing browser hardening header", "severity": "low", "tags": "misconfig,headers"},
        "http": [{
            "method": "GET",
            "path": ["/"],
            "matchers-condition": "or",
            "matchers": [
                {"type": "regex", "part": "header", "negative": True,
                 "regex": [r"(?im)^Content-Security-Policy:"]},
                {"type": "regex", "part": "header", "negative": True,
                 "regex": [r"(?im)^X-Content-Type-Options:"]},
            ],
        }],
    },
    {
            "id": "sql-phpmyadmin-setup-script",
            "info": {
                "name": "phpMyAdmin setup script exposed",
                "severity": "medium",
                "tags": "panel,admin,phpmyadmin,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/phpmyadmin/scripts/setup.php",
                        "/phpMyAdmin/scripts/setup.php"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "phpMyAdmin",
                                "setup.php"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-phpmyadmin-config-file",
            "info": {
                "name": "phpMyAdmin config page exposure",
                "severity": "medium",
                "tags": "panel,admin,phpmyadmin,config,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/phpmyadmin/index.php?route=/server/variables",
                        "/phpMyAdmin/index.php?route=/server/variables"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "phpMyAdmin",
                                "Server variables"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-phpmyadmin-changelog",
            "info": {
                "name": "phpMyAdmin changelog exposure",
                "severity": "info",
                "tags": "metadata,phpmyadmin,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/phpmyadmin/ChangeLog",
                        "/phpMyAdmin/ChangeLog",
                        "/pma/ChangeLog"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "phpMyAdmin",
                                "Changelog"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-adminer-standalone-file",
            "info": {
                "name": "Adminer standalone entrypoint exposed",
                "severity": "medium",
                "tags": "panel,admin,adminer,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/adminer.php",
                        "/db/adminer.php"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "Adminer",
                                "Login - Adminer"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-adminer-login-page",
            "info": {
                "name": "Adminer login page detected",
                "severity": "medium",
                "tags": "panel,admin,adminer,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/adminer/",
                        "/tools/adminer/"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "Adminer",
                                "Login - Adminer",
                                "auth[driver]"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-pgadmin-login-page",
            "info": {
                "name": "pgAdmin login page detected",
                "severity": "medium",
                "tags": "panel,admin,pgadmin,postgresql,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/pgadmin4/login",
                        "/pgadmin/login"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "pgAdmin 4",
                                "login_email",
                                "login_password"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-pgadmin-config-endpoint",
            "info": {
                "name": "pgAdmin misc endpoint exposure",
                "severity": "low",
                "tags": "panel,admin,pgadmin,postgresql,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/pgadmin4/misc/ping",
                        "/pgadmin4/browser/"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "pgAdmin",
                                "application/json"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-mysql-workbench-admin",
            "info": {
                "name": "MySQL admin/workbench web console detected",
                "severity": "medium",
                "tags": "panel,admin,mysql,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/mysql/",
                        "/mysqladmin/"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200,
                                401,
                                403
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "MySQL",
                                "phpMyAdmin"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-mssql-reportserver-login",
            "info": {
                "name": "MSSQL Report Server login detected",
                "severity": "medium",
                "tags": "panel,admin,mssql,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/Reports",
                        "/ReportServer"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200,
                                401,
                                403
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "SQL Server Reporting Services",
                                "Report Server"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-oracle-apex-login",
            "info": {
                "name": "Oracle APEX login detected",
                "severity": "medium",
                "tags": "panel,admin,oracle,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/ords/",
                        "/i/"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "Oracle APEX",
                                "apex_authentication",
                                "f?p="
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-clickhouse-play-ui",
            "info": {
                "name": "ClickHouse web UI detected",
                "severity": "medium",
                "tags": "panel,admin,clickhouse,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/play",
                        "/dashboard"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "ClickHouse",
                                "play.clickhouse.com",
                                "Try ClickHouse"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-dbeaver-web-panel",
            "info": {
                "name": "DBeaver web panel detected",
                "severity": "low",
                "tags": "panel,admin,dbeaver,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/dbeaver",
                        "/dbeaver/"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200,
                                401,
                                403
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "DBeaver",
                                "CloudBeaver"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-phpmyadmin-export-page",
            "info": {
                "name": "phpMyAdmin export page detected",
                "severity": "medium",
                "tags": "panel,phpmyadmin,export,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/phpmyadmin/index.php?route=/server/export",
                        "/phpMyAdmin/index.php?route=/server/export"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "phpMyAdmin",
                                "Export",
                                "SQL"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-phpmyadmin-import-page",
            "info": {
                "name": "phpMyAdmin import page detected",
                "severity": "medium",
                "tags": "panel,phpmyadmin,import,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/phpmyadmin/index.php?route=/server/import",
                        "/phpMyAdmin/index.php?route=/server/import"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "phpMyAdmin",
                                "Import",
                                "SQL"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-adminer-export-page",
            "info": {
                "name": "Adminer export interface detected",
                "severity": "medium",
                "tags": "panel,adminer,export,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/adminer/?dump=1",
                        "/adminer.php?dump=1"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "Adminer",
                                "Export",
                                "SQL command"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-metabase-login",
            "info": {
                "name": "Metabase login panel detected",
                "severity": "medium",
                "tags": "panel,admin,metabase,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/auth/login",
                        "/metabase/auth/login"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "Metabase",
                                "Sign in"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-redash-login",
            "info": {
                "name": "Redash login panel detected",
                "severity": "medium",
                "tags": "panel,admin,redash,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/login",
                        "/redash/login"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "Redash",
                                "Sign In"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-superset-login",
            "info": {
                "name": "Apache Superset login panel detected",
                "severity": "medium",
                "tags": "panel,admin,superset,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/superset/login/",
                        "/login/"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "Superset",
                                "csrf_token",
                                "Welcome to Superset"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-db-backup-sql-file",
            "info": {
                "name": "Database SQL backup file exposed",
                "severity": "high",
                "tags": "exposure,backup,sql,database"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/db_backup.sql",
                        "/database_backup.sql",
                        "/backup/database_backup.sql"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)create\\s+table",
                                "(?i)insert\\s+into",
                                "(?i)dump completed"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-db-backup-gz-file",
            "info": {
                "name": "Compressed SQL backup file exposed",
                "severity": "high",
                "tags": "exposure,backup,sql,database"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/db_backup.sql.gz",
                        "/database.sql.gz",
                        "/backup.sql.gz"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "header",
                            "condition": "or",
                            "words": [
                                "application/gzip",
                                "application/x-gzip",
                                "filename="
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-db-backup-zip-file",
            "info": {
                "name": "Archived SQL backup file exposed",
                "severity": "high",
                "tags": "exposure,backup,sql,database"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/db_backup.zip",
                        "/database_backup.zip",
                        "/sql_backup.zip"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "header",
                            "condition": "or",
                            "words": [
                                "application/zip",
                                "application/x-zip-compressed",
                                "filename="
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-mysql-dump-artifact",
            "info": {
                "name": "MySQL dump artifact exposed",
                "severity": "high",
                "tags": "exposure,mysql,sql,dump"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/mysql.sql",
                        "/mysql_dump.sql",
                        "/dump/mysql.sql"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)--\\s*MySQL dump",
                                "(?i)LOCK TABLES",
                                "(?i)UNLOCK TABLES"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-postgres-dump-artifact",
            "info": {
                "name": "PostgreSQL dump artifact exposed",
                "severity": "high",
                "tags": "exposure,postgresql,sql,dump"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/postgres.sql",
                        "/postgres_dump.sql",
                        "/dump/postgres.sql"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)--\\s*PostgreSQL database dump",
                                "(?i)SET search_path",
                                "(?i)ALTER TABLE ONLY"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-mssql-bak-artifact",
            "info": {
                "name": "MSSQL backup artifact exposed",
                "severity": "high",
                "tags": "exposure,mssql,sql,backup"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/backup.bak",
                        "/database.bak",
                        "/db/backup.bak"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                ".bak",
                                "application/octet-stream",
                                "Microsoft SQL Server"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-sqlite-db-file",
            "info": {
                "name": "SQLite database file exposed",
                "severity": "high",
                "tags": "exposure,sqlite,sql,database"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/db.sqlite",
                        "/db.sqlite3",
                        "/database.sqlite"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "SQLite format 3",
                                "application/octet-stream"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-sqlite-backup-file",
            "info": {
                "name": "SQLite backup file exposed",
                "severity": "high",
                "tags": "exposure,sqlite,sql,backup"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/db.sqlite.bak",
                        "/database.sqlite.bak",
                        "/backup/db.sqlite3"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "SQLite format 3",
                                ".sqlite"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-db-schema-sql-file",
            "info": {
                "name": "Database schema SQL file exposed",
                "severity": "high",
                "tags": "exposure,schema,sql,database"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/schema.sql",
                        "/db/schema.sql",
                        "/sql/schema.sql"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)create\\s+table",
                                "(?i)create\\s+index",
                                "(?i)constraint"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-db-structure-sql-file",
            "info": {
                "name": "Database structure SQL file exposed",
                "severity": "high",
                "tags": "exposure,structure,sql,database"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/structure.sql",
                        "/db/structure.sql"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)create\\s+table",
                                "(?i)primary\\s+key",
                                "(?i)engine\\s*=\\s*innodb"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-db-data-sql-file",
            "info": {
                "name": "Database data SQL file exposed",
                "severity": "high",
                "tags": "exposure,data,sql,database"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/data.sql",
                        "/db/data.sql",
                        "/seed/data.sql"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)insert\\s+into",
                                "(?i)values\\s*\\(",
                                "(?i)transaction"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-production-sql-dump",
            "info": {
                "name": "Production SQL dump exposed",
                "severity": "critical",
                "tags": "exposure,production,sql,dump"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/prod.sql",
                        "/production.sql",
                        "/backup/prod.sql"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)create\\s+database",
                                "(?i)use\\s+`?prod",
                                "(?i)insert\\s+into"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-staging-sql-dump",
            "info": {
                "name": "Staging SQL dump exposed",
                "severity": "high",
                "tags": "exposure,staging,sql,dump"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/staging.sql",
                        "/stage.sql",
                        "/backup/staging.sql"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)create\\s+database",
                                "(?i)staging",
                                "(?i)insert\\s+into"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-old-database-backup",
            "info": {
                "name": "Old database backup artifact exposed",
                "severity": "high",
                "tags": "exposure,backup,sql,database"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/backup_old.sql",
                        "/old_database.sql",
                        "/db_old.sql"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)dump completed",
                                "(?i)create\\s+table",
                                "(?i)insert\\s+into"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-pgpass-file-exposure",
            "info": {
                "name": "PostgreSQL .pgpass file exposed",
                "severity": "critical",
                "tags": "exposure,postgresql,credentials,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/.pgpass",
                        "/home/.pgpass"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?m)^([^:\\n]+):(\\d+|\\*):([^:\\n]+):([^:\\n]+):(.+)$"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-my-cnf-exposure",
            "info": {
                "name": "MySQL my.cnf configuration exposed",
                "severity": "critical",
                "tags": "exposure,mysql,config,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/my.cnf",
                        "/etc/my.cnf",
                        "/.my.cnf"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?im)^\\s*\\[client\\]",
                                "(?im)^\\s*password\\s*=",
                                "(?im)^\\s*user\\s*="
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-mysql-history-exposure",
            "info": {
                "name": "MySQL history file exposed",
                "severity": "medium",
                "tags": "exposure,mysql,history,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/.mysql_history",
                        "/home/.mysql_history"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)select\\s+.+\\s+from",
                                "(?i)update\\s+.+\\s+set",
                                "(?i)delete\\s+from"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-psql-history-exposure",
            "info": {
                "name": "PostgreSQL history file exposed",
                "severity": "medium",
                "tags": "exposure,postgresql,history,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/.psql_history",
                        "/home/.psql_history"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)select\\s+.+\\s+from",
                                "(?i)\\\\c\\s+",
                                "(?i)create\\s+table"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-sql-log-file-exposure",
            "info": {
                "name": "SQL log file exposed",
                "severity": "high",
                "tags": "exposure,logs,sql,database"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/sql.log",
                        "/logs/sql.log",
                        "/var/log/sql.log"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)(select|insert|update|delete)\\s+.+",
                                "(?i)query",
                                "(?i)rows affected"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-query-log-file-exposure",
            "info": {
                "name": "Database query log exposed",
                "severity": "high",
                "tags": "exposure,logs,sql,database"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/query.log",
                        "/logs/query.log",
                        "/mysql-query.log"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)query\\s+time",
                                "(?i)(select|insert|update|delete)\\s+",
                                "(?i)rows_examined"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-transaction-log-disclosure",
            "info": {
                "name": "Database transaction log exposed",
                "severity": "high",
                "tags": "exposure,logs,transaction,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/transaction.log",
                        "/db/transaction.log"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)transaction",
                                "(?i)(commit|rollback)",
                                "(?i)session"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-db-seed-file-exposure",
            "info": {
                "name": "Database seed file exposed",
                "severity": "medium",
                "tags": "exposure,seed,sql,database"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/db/seeds.sql",
                        "/seed.sql",
                        "/database/seeds.sql"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)insert\\s+into",
                                "(?i)seed",
                                "(?i)values\\s*\\("
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-db-fixture-file-exposure",
            "info": {
                "name": "Database fixture SQL exposed",
                "severity": "medium",
                "tags": "exposure,fixture,sql,database"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/db/fixtures.sql",
                        "/fixtures.sql",
                        "/test/fixtures.sql"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)insert\\s+into",
                                "(?i)fixture",
                                "(?i)values\\s*\\("
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-export-sql-artifact",
            "info": {
                "name": "Exported SQL artifact exposed",
                "severity": "high",
                "tags": "exposure,export,sql,database"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/export.sql",
                        "/exports/export.sql",
                        "/sql/export.sql"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)create\\s+table",
                                "(?i)insert\\s+into",
                                "(?i)export"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-export-database-csv",
            "info": {
                "name": "Database export CSV exposed",
                "severity": "medium",
                "tags": "exposure,export,csv,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/export.csv",
                        "/db_export.csv",
                        "/exports/database.csv"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?is)(?=.*\\b(id|user_id|record_id)\\b)(?=.*\\b(email|username|name)\\b)(?=.*\\b(created_at|updated_at|timestamp)\\b)",
                                "(?im)(table_name|schema_name|database_name|row_count|records|exported_at)",
                                "(?i)(mysql|postgres|sqlserver|database export)"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-export-database-json",
            "info": {
                "name": "Database export JSON exposed",
                "severity": "medium",
                "tags": "exposure,export,json,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/export.json",
                        "/db_export.json",
                        "/exports/database.json"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)\"(id|email|created_at)\"\\s*:",
                                "(?i)\"(users|records|rows)\"\\s*:"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-backup-directory-index",
            "info": {
                "name": "Backup directory listing with SQL artifacts",
                "severity": "medium",
                "tags": "misconfig,directory,backup,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/backup/",
                        "/backups/",
                        "/db_backup/"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "Index of",
                                ".sql",
                                ".bak"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-dump-directory-index",
            "info": {
                "name": "Dump directory listing exposed",
                "severity": "medium",
                "tags": "misconfig,directory,dump,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/dump/",
                        "/dumps/",
                        "/sql/"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "Index of",
                                ".sql",
                                "dump"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-config-database-yml",
            "info": {
                "name": "database.yml configuration exposure",
                "severity": "high",
                "tags": "exposure,config,rails,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/config/database.yml",
                        "/database.yml"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?im)^\\s*(development|production|test):",
                                "(?im)^\\s*adapter\\s*:\\s*",
                                "(?im)^\\s*database\\s*:\\s*"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-config-database-yaml",
            "info": {
                "name": "database.yaml configuration exposure",
                "severity": "high",
                "tags": "exposure,config,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/config/database.yaml",
                        "/database.yaml"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?im)^\\s*(development|production|test):",
                                "(?im)^\\s*adapter\\s*:\\s*",
                                "(?im)^\\s*database\\s*:\\s*"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-config-database-json",
            "info": {
                "name": "database.json configuration exposure",
                "severity": "high",
                "tags": "exposure,config,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/config/database.json",
                        "/database.json",
                        "/db/config.json"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)\"(database|db_name)\"\\s*:",
                                "(?i)\"(username|user)\"\\s*:",
                                "(?i)\"(password|passwd)\"\\s*:"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-config-db-php",
            "info": {
                "name": "PHP database config exposure",
                "severity": "high",
                "tags": "exposure,config,php,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/config/db.php",
                        "/app/config/database.php",
                        "/database.php"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)(mysqli?|pdo|pgsql)",
                                "(?i)(password|passwd)\\s*=>",
                                "(?i)(host|hostname)\\s*=>"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-config-connection-strings",
            "info": {
                "name": "Connection string config exposure",
                "severity": "high",
                "tags": "exposure,config,dsn,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/config/connection-strings.json",
                        "/connectionStrings.config",
                        "/appsettings.json"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)(server|host)=.+;(database|db)=",
                                "(?i)(user\\s*id|uid)=",
                                "(?i)(password|pwd)="
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-jdbc-properties-leak",
            "info": {
                "name": "JDBC properties exposure",
                "severity": "high",
                "tags": "exposure,config,jdbc,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/application.properties",
                        "/config/application.properties",
                        "/jdbc.properties"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)^\\s*spring\\.datasource\\.url\\s*=",
                                "(?i)^\\s*spring\\.datasource\\.username\\s*=",
                                "(?i)^\\s*spring\\.datasource\\.password\\s*="
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-jdbc-url-disclosure",
            "info": {
                "name": "JDBC URL disclosure",
                "severity": "medium",
                "tags": "exposure,jdbc,sql,dsn"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/application.yml",
                        "/config/application.yml",
                        "/application.yaml"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)jdbc:(mysql|postgresql|sqlserver|oracle|sqlite):",
                                "(?i)(datasource|database):"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-odbc-ini-disclosure",
            "info": {
                "name": "ODBC ini configuration exposure",
                "severity": "high",
                "tags": "exposure,config,odbc,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/odbc.ini",
                        "/etc/odbc.ini"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?im)^\\s*\\[.*\\]",
                                "(?im)^\\s*Driver\\s*=",
                                "(?im)^\\s*(Server|Database|UID|PWD)\\s*="
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-laravel-env-db-creds",
            "info": {
                "name": "Laravel DB credentials exposure in .env",
                "severity": "critical",
                "tags": "exposure,config,laravel,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/.env",
                        "/app/.env",
                        "/laravel/.env"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?im)^DB_CONNECTION=",
                                "(?im)^DB_HOST=",
                                "(?im)^DB_PASSWORD="
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-rails-database-yml",
            "info": {
                "name": "Rails database.yml metadata exposure",
                "severity": "high",
                "tags": "exposure,rails,config,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/config/database.yml"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?im)^\\s*adapter\\s*:\\s*(postgresql|mysql2|sqlite3)",
                                "(?im)^\\s*database\\s*:\\s*",
                                "(?im)^\\s*username\\s*:\\s*"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-django-settings-db",
            "info": {
                "name": "Django database settings exposure",
                "severity": "high",
                "tags": "exposure,django,config,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/settings.py",
                        "/project/settings.py"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)DATABASES\\s*=\\s*\\{",
                                "(?i)'ENGINE'\\s*:\\s*'django\\.db\\.backends",
                                "(?i)'NAME'\\s*:\\s*"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-wordpress-db-config",
            "info": {
                "name": "WordPress DB configuration exposure",
                "severity": "critical",
                "tags": "exposure,wordpress,config,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/wp-config.php.bak",
                        "/wp-config.php.save",
                        "/wp-config.php~"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)DB_NAME",
                                "(?i)DB_USER",
                                "(?i)DB_PASSWORD"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-drupal-settings-db",
            "info": {
                "name": "Drupal DB configuration exposure",
                "severity": "high",
                "tags": "exposure,drupal,config,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/sites/default/settings.php.bak",
                        "/sites/default/settings.php~"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)\\$databases\\s*=",
                                "(?i)'database'\\s*=>",
                                "(?i)'username'\\s*=>"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-magento-db-config",
            "info": {
                "name": "Magento DB configuration exposure",
                "severity": "high",
                "tags": "exposure,magento,config,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/app/etc/env.php.bak",
                        "/app/etc/local.xml.bak"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)['\"]db['\"]\\s*=>",
                                "(?i)['\"]connection['\"]\\s*=>\\s*['\"](default|core_setup)['\"]",
                                "(?i)['\"](host|dbname|username|password)['\"]\\s*=>\\s*['\"].+['\"]",
                                "(?i)(mysql|pdo_mysql)"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-dsn-parameter-disclosure",
            "info": {
                "name": "DSN parameter disclosure in config",
                "severity": "high",
                "tags": "exposure,dsn,config,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/config.ini",
                        "/settings.ini",
                        "/database.ini"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)(dsn|database_url)\\s*=\\s*(mysql|pgsql|sqlsrv|sqlite)",
                                "(?i)(user(name)?|password)\\s*=\\s*"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-mysql-status-endpoint",
            "info": {
                "name": "MySQL status endpoint exposure",
                "severity": "low",
                "tags": "metadata,mysql,sql,debug"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/mysql/status",
                        "/status/mysql",
                        "/db/status"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "mysql",
                                "Threads_connected",
                                "Uptime"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-mysql-variables-endpoint",
            "info": {
                "name": "MySQL variables endpoint exposure",
                "severity": "low",
                "tags": "metadata,mysql,sql,debug"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/mysql/variables",
                        "/db/variables",
                        "/status/variables"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "max_connections",
                                "sql_mode",
                                "innodb"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-postgres-health-endpoint",
            "info": {
                "name": "PostgreSQL health endpoint exposure",
                "severity": "low",
                "tags": "metadata,postgresql,sql,debug"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/postgres/health",
                        "/db/postgres/health",
                        "/pg/health"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)\"database\"\\s*:\\s*\"postgres",
                                "(?i)\"numbackends\"\\s*:",
                                "(?i)\"max_connections\"\\s*:"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-mssql-server-info-endpoint",
            "info": {
                "name": "MSSQL server info endpoint exposure",
                "severity": "low",
                "tags": "metadata,mssql,sql,debug"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/mssql/info",
                        "/sqlserver/info",
                        "/db/mssql"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)SQL Server.*(version|edition)",
                                "(?i)Microsoft SQL Server.*(version|edition)",
                                "(?i)sqlserver.*productversion"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-database-debug-toolbar",
            "info": {
                "name": "Database debug toolbar exposure",
                "severity": "medium",
                "tags": "debug,toolbar,sql,database"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/__debug__/",
                        "/_debugbar",
                        "/debug"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "SQL Queries",
                                "Debug Toolbar",
                                "Database"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-django-debug-sql-panel",
            "info": {
                "name": "Django debug SQL panel exposure",
                "severity": "medium",
                "tags": "debug,django,sql,panel"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/__debug__/render_panel/?panel_id=SQLPanel",
                        "/__debug__/"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "SQLPanel",
                                "Queries",
                                "django"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-laravel-debugbar-sql",
            "info": {
                "name": "Laravel Debugbar SQL collector exposure",
                "severity": "medium",
                "tags": "debug,laravel,sql,panel"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/_debugbar/open",
                        "/_debugbar/assets/javascript"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "phpdebugbar",
                                "queries",
                                "mysql"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-symfony-profiler-doctrine",
            "info": {
                "name": "Symfony profiler Doctrine data exposure",
                "severity": "medium",
                "tags": "debug,symfony,doctrine,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/_profiler/",
                        "/_profiler/latest?panel=db"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "Doctrine",
                                "Database",
                                "Queries"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-spring-actuator-datasource",
            "info": {
                "name": "Spring actuator datasource exposure",
                "severity": "medium",
                "tags": "debug,spring,actuator,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/actuator/metrics/jdbc.connections.active",
                        "/actuator/env"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)\"name\"\\s*:\\s*\"jdbc\\.connections\\.active\"",
                                "(?i)\"spring\\.datasource\\.(url|username|password)\"",
                                "(?i)\"measurements\"\\s*:\\s*\\["
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-quarkus-datasource-metrics",
            "info": {
                "name": "Quarkus datasource metrics exposure",
                "severity": "low",
                "tags": "debug,quarkus,sql,metrics"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/q/metrics",
                        "/q/health"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "datasource",
                                "jdbc",
                                "connections"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-grafana-sql-datasource",
            "info": {
                "name": "Grafana SQL datasource metadata exposure",
                "severity": "medium",
                "tags": "metadata,grafana,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/api/datasources",
                        "/grafana/api/datasources"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)\"type\"\\s*:\\s*\"mysql\"",
                                "(?i)\"type\"\\s*:\\s*\"postgres\"",
                                "(?i)\"access\"\\s*:\\s*\"proxy\""
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-db-admin-subdomain-panel",
            "info": {
                "name": "Database admin panel on db subpath detected",
                "severity": "medium",
                "tags": "panel,admin,sql,database"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/dbadmin/",
                        "/database-admin/",
                        "/sqladmin/"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "SQL Admin",
                                "dbadmin",
                                "Adminer",
                                "pgAdmin"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-graphql-introspection-sql-fields",
            "info": {
                "name": "GraphQL SQL-related schema fields exposed",
                "severity": "low",
                "tags": "graphql,metadata,sql,api"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/graphql",
                        "/api/graphql"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "__schema",
                                "GraphQL",
                                "databaseUrl"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-openapi-sql-schema-leak",
            "info": {
                "name": "OpenAPI schema leaks SQL backend details",
                "severity": "low",
                "tags": "openapi,metadata,sql,api"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/openapi.json",
                        "/swagger.json",
                        "/v3/api-docs"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)jdbc:postgresql://",
                                "(?i)jdbc:mysql://",
                                "(?i)(server|host)=.+;(database|db)="
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-database-endpoint-swagger-example",
            "info": {
                "name": "Swagger examples contain SQL endpoints",
                "severity": "low",
                "tags": "swagger,metadata,sql,api"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/swagger-ui.html",
                        "/swagger/index.html"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)\"/api/(db|database|sql)/",
                                "(?i)\"operationId\"\\s*:\\s*\".*(sql|database).*\"",
                                "(?i)\"summary\"\\s*:\\s*\".*(database|sql).*\""
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-liquibase-changelog",
            "info": {
                "name": "Liquibase changelog file exposure",
                "severity": "medium",
                "tags": "exposure,liquibase,migration,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/db/changelog/db.changelog-master.xml",
                        "/changelog.xml"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "databaseChangeLog",
                                "changeSet",
                                "sql"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-flyway-history-table-dump",
            "info": {
                "name": "Flyway schema history dump exposure",
                "severity": "medium",
                "tags": "exposure,flyway,migration,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/flyway_schema_history.sql",
                        "/db/flyway_schema_history.sql"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "flyway_schema_history",
                                "installed_rank",
                                "script"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-db-migration-files",
            "info": {
                "name": "Database migration SQL file exposure",
                "severity": "medium",
                "tags": "exposure,migration,sql,database"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/migrations/",
                        "/db/migrate/",
                        "/database/migrations/"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "Index of",
                                ".sql"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-sql-error-disclosure-root",
            "info": {
                "name": "SQL error disclosure on root page",
                "severity": "medium",
                "tags": "exposure,error,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200,
                                500
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)sql syntax.*mysql",
                                "(?i)warning.*mysql_",
                                "(?i)unclosed quotation mark after the character string",
                                "(?i)quoted string not properly terminated",
                                "(?i)pg_query\\(\\)",
                                "(?i)psql:.*error",
                                "(?i)microsoft odbc sql server driver",
                                "(?i)sqlite\\s*error",
                                "(?i)you have an error in your sql syntax"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-sql-error-disclosure-api",
            "info": {
                "name": "SQL error disclosure on API endpoint",
                "severity": "medium",
                "tags": "exposure,error,api,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/api",
                        "/api/v1",
                        "/api/v2"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200,
                                400,
                                500
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)sql syntax.*mysql",
                                "(?i)warning.*mysql_",
                                "(?i)unclosed quotation mark after the character string",
                                "(?i)quoted string not properly terminated",
                                "(?i)pg_query\\(\\)",
                                "(?i)psql:.*error",
                                "(?i)microsoft odbc sql server driver",
                                "(?i)sqlite\\s*error",
                                "(?i)you have an error in your sql syntax"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-sql-error-disclosure-search",
            "info": {
                "name": "SQL error disclosure on search endpoint",
                "severity": "medium",
                "tags": "exposure,error,search,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/search?q='",
                        "/search?query='",
                        "/api/search?q='"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200,
                                400,
                                500
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)sql syntax.*mysql",
                                "(?i)warning.*mysql_",
                                "(?i)unclosed quotation mark after the character string",
                                "(?i)quoted string not properly terminated",
                                "(?i)pg_query\\(\\)",
                                "(?i)psql:.*error",
                                "(?i)microsoft odbc sql server driver",
                                "(?i)sqlite\\s*error",
                                "(?i)you have an error in your sql syntax"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-sql-error-disclosure-login",
            "info": {
                "name": "SQL error disclosure on login endpoint",
                "severity": "medium",
                "tags": "exposure,error,auth,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/login",
                        "/user/login",
                        "/auth/login"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200,
                                400,
                                500
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)sql syntax.*mysql",
                                "(?i)warning.*mysql_",
                                "(?i)unclosed quotation mark after the character string",
                                "(?i)quoted string not properly terminated",
                                "(?i)pg_query\\(\\)",
                                "(?i)psql:.*error",
                                "(?i)microsoft odbc sql server driver",
                                "(?i)sqlite\\s*error",
                                "(?i)you have an error in your sql syntax"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-sql-error-disclosure-register",
            "info": {
                "name": "SQL error disclosure on register endpoint",
                "severity": "medium",
                "tags": "exposure,error,auth,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/register",
                        "/signup",
                        "/user/register"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200,
                                400,
                                500
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)sql syntax.*mysql",
                                "(?i)warning.*mysql_",
                                "(?i)unclosed quotation mark after the character string",
                                "(?i)quoted string not properly terminated",
                                "(?i)pg_query\\(\\)",
                                "(?i)psql:.*error",
                                "(?i)microsoft odbc sql server driver",
                                "(?i)sqlite\\s*error",
                                "(?i)you have an error in your sql syntax"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-sql-error-disclosure-filter",
            "info": {
                "name": "SQL error disclosure on filter endpoint",
                "severity": "medium",
                "tags": "exposure,error,filter,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/products?sort='",
                        "/items?filter='",
                        "/api/items?order='"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200,
                                400,
                                500
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)sql syntax.*mysql",
                                "(?i)warning.*mysql_",
                                "(?i)unclosed quotation mark after the character string",
                                "(?i)quoted string not properly terminated",
                                "(?i)pg_query\\(\\)",
                                "(?i)psql:.*error",
                                "(?i)microsoft odbc sql server driver",
                                "(?i)sqlite\\s*error",
                                "(?i)you have an error in your sql syntax"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-sql-error-disclosure-graphql",
            "info": {
                "name": "SQL error disclosure on GraphQL endpoint",
                "severity": "medium",
                "tags": "exposure,error,graphql,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/graphql",
                        "/api/graphql"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200,
                                400,
                                500
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)sql syntax.*mysql",
                                "(?i)warning.*mysql_",
                                "(?i)unclosed quotation mark after the character string",
                                "(?i)quoted string not properly terminated",
                                "(?i)pg_query\\(\\)",
                                "(?i)psql:.*error",
                                "(?i)microsoft odbc sql server driver",
                                "(?i)sqlite\\s*error",
                                "(?i)you have an error in your sql syntax"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-sql-error-disclosure-rest",
            "info": {
                "name": "SQL error disclosure on REST endpoint",
                "severity": "medium",
                "tags": "exposure,error,rest,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/api/users?id='",
                        "/api/orders?id='"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200,
                                400,
                                500
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)sql syntax.*mysql",
                                "(?i)warning.*mysql_",
                                "(?i)unclosed quotation mark after the character string",
                                "(?i)quoted string not properly terminated",
                                "(?i)pg_query\\(\\)",
                                "(?i)psql:.*error",
                                "(?i)microsoft odbc sql server driver",
                                "(?i)sqlite\\s*error",
                                "(?i)you have an error in your sql syntax"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-mysql-syntax-error-message",
            "info": {
                "name": "MySQL syntax error message disclosure",
                "severity": "medium",
                "tags": "exposure,error,mysql,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/",
                        "/index.php?id='"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200,
                                500
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)sql syntax.*mysql",
                                "(?i)warning.*mysql_",
                                "(?i)unclosed quotation mark after the character string",
                                "(?i)quoted string not properly terminated",
                                "(?i)pg_query\\(\\)",
                                "(?i)psql:.*error",
                                "(?i)microsoft odbc sql server driver",
                                "(?i)sqlite\\s*error",
                                "(?i)you have an error in your sql syntax",
                                "(?i)mysql_fetch_array",
                                "(?i)mysqli_sql_exception"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-postgres-syntax-error-message",
            "info": {
                "name": "PostgreSQL syntax error message disclosure",
                "severity": "medium",
                "tags": "exposure,error,postgresql,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/",
                        "/posts?id='"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200,
                                500
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)sql syntax.*mysql",
                                "(?i)warning.*mysql_",
                                "(?i)unclosed quotation mark after the character string",
                                "(?i)quoted string not properly terminated",
                                "(?i)pg_query\\(\\)",
                                "(?i)psql:.*error",
                                "(?i)microsoft odbc sql server driver",
                                "(?i)sqlite\\s*error",
                                "(?i)you have an error in your sql syntax",
                                "(?i)postgresql.*error",
                                "(?i)pg::syntaxerror"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-mssql-syntax-error-message",
            "info": {
                "name": "MSSQL syntax error message disclosure",
                "severity": "medium",
                "tags": "exposure,error,mssql,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/",
                        "/news?id='"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200,
                                500
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)sql syntax.*mysql",
                                "(?i)warning.*mysql_",
                                "(?i)unclosed quotation mark after the character string",
                                "(?i)quoted string not properly terminated",
                                "(?i)pg_query\\(\\)",
                                "(?i)psql:.*error",
                                "(?i)microsoft odbc sql server driver",
                                "(?i)sqlite\\s*error",
                                "(?i)you have an error in your sql syntax",
                                "(?i)sqlserverexception",
                                "(?i)microsoft sql native client"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-oracle-syntax-error-message",
            "info": {
                "name": "Oracle SQL error message disclosure",
                "severity": "medium",
                "tags": "exposure,error,oracle,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/",
                        "/article?id='"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200,
                                500
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)sql syntax.*mysql",
                                "(?i)warning.*mysql_",
                                "(?i)unclosed quotation mark after the character string",
                                "(?i)quoted string not properly terminated",
                                "(?i)pg_query\\(\\)",
                                "(?i)psql:.*error",
                                "(?i)microsoft odbc sql server driver",
                                "(?i)sqlite\\s*error",
                                "(?i)you have an error in your sql syntax",
                                "(?i)ORA-00933",
                                "(?i)ORA-01756"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-sqlite-error-message",
            "info": {
                "name": "SQLite error message disclosure",
                "severity": "medium",
                "tags": "exposure,error,sqlite,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/",
                        "/page?id='"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200,
                                500
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)sql syntax.*mysql",
                                "(?i)warning.*mysql_",
                                "(?i)unclosed quotation mark after the character string",
                                "(?i)quoted string not properly terminated",
                                "(?i)pg_query\\(\\)",
                                "(?i)psql:.*error",
                                "(?i)microsoft odbc sql server driver",
                                "(?i)sqlite\\s*error",
                                "(?i)you have an error in your sql syntax",
                                "(?i)SQLiteException",
                                "(?i)near \".*\": syntax error"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-jdbc-stacktrace-disclosure",
            "info": {
                "name": "JDBC SQL stack trace disclosure",
                "severity": "medium",
                "tags": "exposure,error,jdbc,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/",
                        "/api"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200,
                                500
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)sql syntax.*mysql",
                                "(?i)warning.*mysql_",
                                "(?i)unclosed quotation mark after the character string",
                                "(?i)quoted string not properly terminated",
                                "(?i)pg_query\\(\\)",
                                "(?i)psql:.*error",
                                "(?i)microsoft odbc sql server driver",
                                "(?i)sqlite\\s*error",
                                "(?i)you have an error in your sql syntax",
                                "(?i)java\\.sql\\.SQLException",
                                "(?i)jdbc:"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-hibernate-sql-disclosure",
            "info": {
                "name": "Hibernate SQL exception disclosure",
                "severity": "medium",
                "tags": "exposure,error,hibernate,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/",
                        "/api"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200,
                                500
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)sql syntax.*mysql",
                                "(?i)warning.*mysql_",
                                "(?i)unclosed quotation mark after the character string",
                                "(?i)quoted string not properly terminated",
                                "(?i)pg_query\\(\\)",
                                "(?i)psql:.*error",
                                "(?i)microsoft odbc sql server driver",
                                "(?i)sqlite\\s*error",
                                "(?i)you have an error in your sql syntax",
                                "(?i)org\\.hibernate\\.exception",
                                "(?i)could not execute statement"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-sequelize-sql-disclosure",
            "info": {
                "name": "Sequelize SQL error disclosure",
                "severity": "medium",
                "tags": "exposure,error,sequelize,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/",
                        "/api"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200,
                                500
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)sql syntax.*mysql",
                                "(?i)warning.*mysql_",
                                "(?i)unclosed quotation mark after the character string",
                                "(?i)quoted string not properly terminated",
                                "(?i)pg_query\\(\\)",
                                "(?i)psql:.*error",
                                "(?i)microsoft odbc sql server driver",
                                "(?i)sqlite\\s*error",
                                "(?i)you have an error in your sql syntax",
                                "(?i)SequelizeDatabaseError",
                                "(?i)original:\\s*error"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-sqlalchemy-error-disclosure",
            "info": {
                "name": "SQLAlchemy error disclosure",
                "severity": "medium",
                "tags": "exposure,error,sqlalchemy,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/",
                        "/api"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200,
                                500
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)sql syntax.*mysql",
                                "(?i)warning.*mysql_",
                                "(?i)unclosed quotation mark after the character string",
                                "(?i)quoted string not properly terminated",
                                "(?i)pg_query\\(\\)",
                                "(?i)psql:.*error",
                                "(?i)microsoft odbc sql server driver",
                                "(?i)sqlite\\s*error",
                                "(?i)you have an error in your sql syntax",
                                "(?i)sqlalchemy\\.exc",
                                "(?i)statement:\\s*select"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-entityframework-sql-error",
            "info": {
                "name": "Entity Framework SQL error disclosure",
                "severity": "medium",
                "tags": "exposure,error,entityframework,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/",
                        "/api"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200,
                                500
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)sql syntax.*mysql",
                                "(?i)warning.*mysql_",
                                "(?i)unclosed quotation mark after the character string",
                                "(?i)quoted string not properly terminated",
                                "(?i)pg_query\\(\\)",
                                "(?i)psql:.*error",
                                "(?i)microsoft odbc sql server driver",
                                "(?i)sqlite\\s*error",
                                "(?i)you have an error in your sql syntax",
                                "(?i)EntityFramework",
                                "(?i)SqlException"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-prisma-sql-error",
            "info": {
                "name": "Prisma SQL error disclosure",
                "severity": "medium",
                "tags": "exposure,error,prisma,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/",
                        "/api"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200,
                                500
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)sql syntax.*mysql",
                                "(?i)warning.*mysql_",
                                "(?i)unclosed quotation mark after the character string",
                                "(?i)quoted string not properly terminated",
                                "(?i)pg_query\\(\\)",
                                "(?i)psql:.*error",
                                "(?i)microsoft odbc sql server driver",
                                "(?i)sqlite\\s*error",
                                "(?i)you have an error in your sql syntax",
                                "(?i)PrismaClientKnownRequestError",
                                "(?i)P10\\d{2}",
                                "(?i)P20\\d{2}"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-knex-sql-error",
            "info": {
                "name": "Knex SQL error disclosure",
                "severity": "medium",
                "tags": "exposure,error,knex,sql"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/",
                        "/api"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200,
                                500
                            ]
                        },
                        {
                            "type": "regex",
                            "part": "body",
                            "condition": "or",
                            "regex": [
                                "(?i)sql syntax.*mysql",
                                "(?i)warning.*mysql_",
                                "(?i)unclosed quotation mark after the character string",
                                "(?i)quoted string not properly terminated",
                                "(?i)pg_query\\(\\)",
                                "(?i)psql:.*error",
                                "(?i)microsoft odbc sql server driver",
                                "(?i)sqlite\\s*error",
                                "(?i)you have an error in your sql syntax",
                                "(?i)KnexTimeoutError",
                                "(?i)Undefined binding\\(s\\)"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "sql-mysql-performance-schema",
            "info": {
                "name": "MySQL performance schema endpoint exposure",
                "severity": "low",
                "tags": "metadata,mysql,sql,debug"
            },
            "http": [
                {
                    "method": "GET",
                    "path": [
                        "/mysql/performance",
                        "/performance_schema"
                    ],
                    "matchers-condition": "and",
                    "matchers": [
                        {
                            "type": "status",
                            "status": [
                                200
                            ]
                        },
                        {
                            "type": "word",
                            "part": "body",
                            "condition": "or",
                            "words": [
                                "performance_schema",
                                "events_statements",
                                "threads"
                            ]
                        }
                    ]
                }
            ]
        }
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


def flatten_extracted_items(items):
    flattened = []
    for item in items or []:
        if isinstance(item, tuple):
            flattened.append(" = ".join(str(part) for part in item if str(part).strip()))
        else:
            flattened.append(str(item))
    return flattened


def get_header_value(resp, header_name):
    for key, value in resp.headers.items():
        if key.lower() == header_name.lower():
            return value
    return ""


def is_text_like_response(resp):
    content_type = (get_header_value(resp, "Content-Type") or "").lower()
    return any(token in content_type for token in TEXT_LIKE_CONTENT_TYPES)


def looks_like_soft_404(resp, body_text):
    if resp.status_code in {404, 410}:
        return True

    if resp.status_code in {401, 403}:
        return True

    snippet = (body_text or "")[:4000]
    return any(re.search(pattern, snippet, re.IGNORECASE) for pattern in SOFT_404_BODY_PATTERNS)


def should_skip_false_positive(template_id, resp, body_text):
    text_like = is_text_like_response(resp)
    soft_404 = looks_like_soft_404(resp, body_text)
    body_lower = (body_text or "").lower()
    content_type = (get_header_value(resp, "Content-Type") or "").lower()
    content_length = get_header_value(resp, "Content-Length") or ""

    if template_id in {
        "git-config-exposure",
        "git-head-exposure",
        "git-commit-editmsg-exposure",
        "git-logs-exposure",
        "gitignore-exposure",
        "gitmodules-exposure",
        "svn-entries-exposure",
        "mercurial-repo-exposure",
        "composer-files-exposure",
        "docker-files-exposure",
        "config-json-exposure",
        "dotenv-exposure",
        "wp-config-exposure",
        "sensitive-ssh-files-exposure",
    }:
        if soft_404:
            return True

    if template_id == "phpinfo-exposure" and (soft_404 or "phpinfo()" not in body_lower and "php version" not in body_lower):
        return True

    if template_id == "dsstore-exposure" and text_like:
        return True

    if template_id in {"backup-files-exposure", "docker-files-exposure"}:
        if soft_404:
            return True
        if text_like and "zip" not in content_type and "gzip" not in content_type and "tar" not in content_type and "sql" not in content_type:
            return True

    if template_id == "directory-listing-enabled":
        if soft_404:
            return True
        if "index of /" not in body_lower and "parent directory" not in body_lower:
            return True

    if template_id == "cors-wildcard-misconfig" and soft_404:
        return True

    if template_id == "wordpress-detect":
        if soft_404:
            return True
        if "/wp-" not in body_lower and "wp-content" not in body_lower and "wp-includes" not in body_lower and "x-powered-by: php" not in "\n".join(f"{k}: {v}" for k, v in resp.headers.items()).lower():
            return True

    if template_id == "server-header-disclosure":
        if not get_header_value(resp, "Server") and not get_header_value(resp, "X-Powered-By"):
            return True

    if template_id in {"cookies-missing-secure", "cookies-missing-httponly", "cookies-missing-samesite"}:
        cookies = parse_set_cookie_headers(resp)
        if not any(c.get("is_auth") for c in cookies):
            return True

    if template_id in {"swagger-ui-detect", "graphql-endpoint-detect", "spring-actuator-exposure", "status-endpoint-metadata", "health-endpoint-metadata", "prometheus-metrics-discovery"} and soft_404:
        return True

    if template_id == "elasticsearch-open-instance":
        if soft_404 or '"cluster_name"' not in body_text:
            return True

    if template_id == "public-email-disclosure" and soft_404:
        return True

    if template_id == "javascript-sourcemap-exposure":
        if soft_404:
            return True
        if '"version"' not in body_text and '"sources"' not in body_text:
            return True

    if template_id == "robots-txt-discovery" and soft_404:
        return True

    if template_id == "sitemap-xml-discovery" and (soft_404 or "<urlset" not in body_lower and "<sitemapindex" not in body_lower):
        return True

    if template_id == "browserconfig-xml-discovery" and (soft_404 or "<browserconfig" not in body_lower):
        return True

    if template_id in {"readme-public-discovery", "changelog-public-discovery", "license-public-discovery"}:
        if soft_404 or not text_like:
            return True

    if template_id in {"package-lock-exposure", "pnpm-lock-exposure", "requirements-txt-discovery", "pyproject-toml-discovery", "dockerignore-public-discovery", "editorconfig-public-discovery", "env-example-public-discovery", "gitignore-public-discovery"}:
        if soft_404:
            return True

    if template_id in {"git-commit-editmsg-exposure", "readme-public-discovery", "changelog-public-discovery", "license-public-discovery"}:
        if content_length == "0":
            return True

    return False


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

    return flatten_extracted_items(found)[:10]


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
                    if should_skip_false_positive(tpl.get("id"), resp, body_text):
                        continue
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
                    break
    return target, findings


# ------------------------------------------------------------------ #
# Output
# ------------------------------------------------------------------ #
def print_finding(finding):
    sev = finding["severity"].lower()
    color = SEVERITY_COLOR.get(sev, RESET)
    tags = f"{GREY}[{finding['tags']}]{RESET}" if finding.get("tags") else ""
    print(f"{color}[{sev.upper():^8}]{RESET} {BOLD}{finding['template']}{RESET} {tags}")
    print(f"    {GREEN}→{RESET} {finding['matched_url']}  {GREY}({finding['status_code']}){RESET}")
    if finding.get("extracted"):
        print(f"    {CYAN}extracted:{RESET} {finding['extracted']}")


def write_output(all_results, out_path):
    ext = os.path.splitext(out_path)[1].lower()
    if ext == ".json":
        with open(out_path, "w") as f:
            json.dump(all_results, f, indent=2)
    elif ext == ".csv":
        import csv
        with open(out_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["target", "template", "severity", "tags", "matched_url", "status_code", "extracted"])
            for target, findings in all_results.items():
                for finding in findings:
                    extracted = finding.get("extracted", [])
                    flattened = [str(item) for item in extracted]
                    writer.writerow([
                        target,
                        finding["template"],
                        finding["severity"],
                        finding["tags"],
                        finding["matched_url"],
                        finding["status_code"],
                        ";".join(flattened),
                    ])
    else:
        with open(out_path, "w") as f:
            for target, findings in all_results.items():
                for finding in findings:
                    f.write(
                        f"[{finding['severity'].upper()}] {finding['template']} -> "
                        f"{finding['matched_url']} ({finding['status_code']})\n"
                    )


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
        futures = {pool.submit(scan_target, target, templates, args.timeout): target for target in targets}
        for fut in concurrent.futures.as_completed(futures):
            target, findings = fut.result()
            all_results[target] = findings
            if findings:
                print(f"{BOLD}{CYAN}== {target} =={RESET}")
                for finding in findings:
                    print_finding(finding)
                    total_findings += 1
                print()

    elapsed = time.time() - start
    print(f"{GREY}[*] scan complete in {elapsed:.1f}s — {total_findings} finding(s) across {len(targets)} target(s){RESET}")

    if args.output:
        write_output(all_results, args.output)
        print(f"{GREEN}[+] results written to {args.output}{RESET}")


if __name__ == "__main__":
    main()
