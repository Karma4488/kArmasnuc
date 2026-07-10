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
    {
        "id": "svn-entries-exposure",
        "info": {"name": "Exposed Subversion metadata", "severity": "high", "tags": "exposure,svn,config"},
        "http": [{
            "method": "GET",
            "path": ["/.svn/entries"],
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
            "path": ["/app/config.json", "/config/config.json", "/assets/config.json", "/static/config.json"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"""(?i)['"]?(api[_-]?key|client[_-]?secret|jwt[_-]?secret|db[_-]?password|access[_-]?key[_-]?id)['"]?\s*:\s*['"][^'"]{4,}['"]"""]},
            ],
        }],
    },
    {
        "id": "npmrc-exposure",
        "info": {"name": "Exposed .npmrc file", "severity": "critical", "tags": "exposure,npm,secrets"},
        "http": [{
            "method": "GET",
            "path": ["/.npmrc"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)_authToken\s*=", r"(?i)//registry\..*:_(auth|password)\s*="]},
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
            "path": ["/phpmyadmin/", "/phpMyAdmin/", "/pma/", "/adminer.php", "/adminer/",
                     "/pgadmin/", "/pgadmin4/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["phpMyAdmin", "Adminer", "pgAdmin 4", "pgAdmin"]},
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
                {"type": "status", "status": [200]},
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
                 "regex": [r'"cluster_name"\s*:', r'"tagline"\s*:\s*"You Know, for Search"',
                           r'"status"\s*:\s*"(green|yellow|red)"']},
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
            "path": ["/graphql", "/graphql/", "/api/graphql", "/api/v1/graphql", "/query"],
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
                 "regex": [r'"status"\s*:\s*"(UP|DOWN|OUT_OF_SERVICE|UNKNOWN)"',
                           r'"activeProfiles"\s*:', r'"propertySources"\s*:']},
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
                           r"(?sm)^\s*Host\s+\S+.*^\s*(IdentityFile|User|Port|StrictHostKeyChecking|ProxyCommand)\s+\S+"]},
            ],
        }],
    },
    {
        "id": "missing-browser-hardening-headers",
        "info": {"name": "Missing browser hardening header", "severity": "low", "tags": "misconfig,headers"},
        "http": [
            {
                "method": "GET",
                "path": ["/"],
                "matchers-condition": "and",
                "matchers": [
                    {"type": "status", "status": [200]},
                    {"type": "header_absent", "header": "Content-Security-Policy"},
                ],
            },
            {
                "method": "GET",
                "path": ["/"],
                "matchers-condition": "and",
                "matchers": [
                    {"type": "status", "status": [200]},
                    {"type": "header_absent", "header": "X-Content-Type-Options"},
                ],
            },
        ],
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
