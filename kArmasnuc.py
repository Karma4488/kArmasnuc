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
<<<<<<< HEAD

    # ------------------------------------------------------------------ #
    # VCS / Source Control Exposure
    # ------------------------------------------------------------------ #
    {
        "id": "git-head-exposure",
        "info": {"name": "Exposed .git/HEAD file", "severity": "high", "tags": "exposure,git,vcs"},
        "http": [{
            "method": "GET",
            "path": ["/.git/HEAD"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r"ref:\s*refs/heads/"]},
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
                {"type": "regex", "part": "header",
                 "regex": [r"(?i)Content-Type:\s*text/plain"]},
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
                {"type": "regex", "part": "body",
                 "regex": [r"[0-9a-f]{40}"]},
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
                 "regex": [r"(?m)^\s*[#*!]", r"(?m)^\s*\*\.\w+",
                            r"(?m)^/?[\w./-]+(\.[\w]+)?$"]},
            ],
        }],
    },
    {
        "id": "gitmodules-exposure",
        "info": {"name": "Exposed .gitmodules (submodule path/URL disclosure)", "severity": "low",
                  "tags": "exposure,git,vcs"},
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
        "info": {"name": "Exposed .svn/entries (Subversion repository)", "severity": "high",
                  "tags": "exposure,svn,vcs"},
        "http": [{
            "method": "GET",
            "path": ["/.svn/entries", "/.svn/wc.db"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                # .svn/entries starts with a plain integer version line ("10\n")
                # followed by a blank line and then entry records; require both
                # the version-line shape and at least one svn: field.
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)svn:", r"(?ms)^\d+\n\n"]},
            ],
        }],
    },
    {
        "id": "hg-requires-exposure",
        "info": {"name": "Exposed .hg/requires (Mercurial repository)", "severity": "high",
                  "tags": "exposure,mercurial,vcs"},
        "http": [{
            "method": "GET",
            "path": ["/.hg/requires"],
=======
    {
        "id": "svn-entries-exposure",
        "info": {"name": "Exposed Subversion metadata", "severity": "high", "tags": "exposure,svn,config"},
        "http": [{
            "method": "GET",
            "path": ["/.svn/entries"],
>>>>>>> origin/main
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
<<<<<<< HEAD
                 "regex": [r"(?i)revlogv1", r"(?i)store", r"(?i)fncache"]},
=======
                 "regex": [r"(?m)^dir\s*$", r"(?m)^\d+\s*$", r"(?m)^svn:.*$"]},
>>>>>>> origin/main
            ],
        }],
    },
    {
<<<<<<< HEAD
        "id": "hg-hgrc-exposure",
        "info": {"name": "Exposed .hg/hgrc (Mercurial config)", "severity": "high",
                  "tags": "exposure,mercurial,vcs"},
        "http": [{
            "method": "GET",
            "path": ["/.hg/hgrc"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "words": ["[paths]"]},
            ],
        }],
    },

    # ------------------------------------------------------------------ #
    # Package / Dependency Metadata Exposure
    # ------------------------------------------------------------------ #
    {
        "id": "composer-json-exposure",
        "info": {"name": "Exposed composer.json (PHP dependency manifest)", "severity": "medium",
                  "tags": "exposure,php,packages"},
        "http": [{
            "method": "GET",
            "path": ["/composer.json"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ['"require"', '"require-dev"', '"autoload"']},
            ],
        }],
    },
    {
        "id": "composer-lock-exposure",
        "info": {"name": "Exposed composer.lock (exact PHP dependency versions)", "severity": "medium",
                  "tags": "exposure,php,packages"},
        "http": [{
            "method": "GET",
            "path": ["/composer.lock"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "words": ['"packages"']},
            ],
        }],
    },
    {
        "id": "package-json-exposure",
        "info": {"name": "Exposed package.json (Node.js dependency manifest)", "severity": "medium",
                  "tags": "exposure,nodejs,packages"},
        "http": [{
            "method": "GET",
            "path": ["/package.json"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ['"dependencies"', '"devDependencies"', '"scripts"']},
            ],
        }],
    },
    {
        "id": "yarn-lock-exposure",
        "info": {"name": "Exposed yarn.lock (Node.js exact dependency lock file)", "severity": "medium",
                  "tags": "exposure,nodejs,packages"},
        "http": [{
            "method": "GET",
            "path": ["/yarn.lock"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r"# yarn lockfile"]},
            ],
        }],
    },
    {
        "id": "pom-xml-exposure",
        "info": {"name": "Exposed pom.xml (Maven project descriptor)", "severity": "medium",
                  "tags": "exposure,java,maven,packages"},
        "http": [{
            "method": "GET",
            "path": ["/pom.xml"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["<groupId>", "<artifactId>", "<dependencies>"]},
            ],
        }],
    },
    {
        "id": "requirements-txt-exposure",
        "info": {"name": "Exposed requirements.txt (Python dependencies)", "severity": "low",
                  "tags": "exposure,python,packages"},
        "http": [{
            "method": "GET",
            "path": ["/requirements.txt", "/requirements/base.txt",
                     "/requirements/prod.txt", "/requirements/production.txt"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r"(?m)^[\w-]+[>=<!~\[\]]"]},
            ],
        }],
    },
    {
        "id": "gemfile-exposure",
        "info": {"name": "Exposed Gemfile (Ruby dependency manifest)", "severity": "low",
                  "tags": "exposure,ruby,packages"},
        "http": [{
            "method": "GET",
            "path": ["/Gemfile"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)source\s+['\"]https?://", r"(?i)gem\s+['\"]"]},
            ],
        }],
    },
    {
        "id": "go-mod-exposure",
        "info": {"name": "Exposed go.mod (Go module file)", "severity": "low",
                  "tags": "exposure,golang,packages"},
        "http": [{
            "method": "GET",
            "path": ["/go.mod"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"^module\s+\S+", r"^go\s+\d+\.\d+"]},
            ],
        }],
    },

    # ------------------------------------------------------------------ #
    # API Documentation / Schema Exposure
    # ------------------------------------------------------------------ #
    {
        "id": "swagger-ui-exposure",
        "info": {"name": "Exposed Swagger / OpenAPI UI", "severity": "medium",
                  "tags": "exposure,api,swagger"},
        "http": [{
            "method": "GET",
            "path": ["/swagger-ui.html", "/swagger-ui/", "/swagger/",
                     "/swagger/index.html", "/api/swagger-ui.html"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)swagger", r"(?i)SwaggerUI", r"(?i)swagger-ui"]},
            ],
        }],
    },
    {
        "id": "openapi-json-exposure",
        "info": {"name": "Exposed OpenAPI / Swagger JSON schema", "severity": "medium",
                  "tags": "exposure,api,swagger,openapi"},
        "http": [{
            "method": "GET",
            "path": ["/openapi.json", "/openapi.yaml", "/api-docs",
                     "/api/openapi.json", "/v1/api-docs", "/v2/api-docs",
                     "/v3/api-docs"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"openapi":\s*"[23]\.', r'"swagger":\s*"[12]\.',
                            r"(?i)openapi:\s*['\"]?[23]\."]},
            ],
        }],
    },
    {
        "id": "graphql-introspection-exposure",
        "info": {"name": "GraphQL endpoint detected (potential introspection)", "severity": "medium",
                  "tags": "exposure,api,graphql"},
        "http": [{
            "method": "GET",
            "path": ["/graphql", "/api/graphql", "/graphiql", "/playground"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)graphql", r"(?i)graphiql", r"(?i)__schema"]},
            ],
        }],
    },
    {
        "id": "postman-collection-exposure",
        "info": {"name": "Exposed Postman collection file", "severity": "medium",
                  "tags": "exposure,api,postman"},
        "http": [{
            "method": "GET",
            "path": ["/postman_collection.json", "/collection.json",
                     "/api-collection.json"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ['"info"', '"collection"', '"postman_id"']},
            ],
        }],
    },

    # ------------------------------------------------------------------ #
    # Debug / Status Endpoints
    # ------------------------------------------------------------------ #
    {
        "id": "apache-server-status",
        "info": {"name": "Apache mod_status exposed (/server-status)", "severity": "medium",
                  "tags": "exposure,apache,debug"},
        "http": [{
            "method": "GET",
            "path": ["/server-status", "/server-status?auto"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)Apache Server Status", r"(?i)Server Version",
                            r"(?i)Total accesses", r"(?i)Current Time"]},
            ],
        }],
    },
    {
        "id": "apache-server-info",
        "info": {"name": "Apache mod_info exposed (/server-info)", "severity": "medium",
                  "tags": "exposure,apache,debug"},
        "http": [{
            "method": "GET",
            "path": ["/server-info"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)Apache Server Information", r"(?i)Server Settings"]},
            ],
        }],
    },
    {
        "id": "spring-actuator-health",
        "info": {"name": "Spring Boot Actuator /health endpoint exposed", "severity": "low",
                  "tags": "exposure,spring,actuator,java"},
        "http": [{
            "method": "GET",
            "path": ["/actuator/health", "/health"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r'"status"\s*:\s*"(UP|DOWN|OUT_OF_SERVICE)"']},
            ],
        }],
    },
    {
        "id": "spring-actuator-env",
        "info": {"name": "Spring Boot Actuator /env endpoint exposed (config disclosure)", "severity": "high",
                  "tags": "exposure,spring,actuator,java,config"},
        "http": [{
            "method": "GET",
            "path": ["/actuator/env", "/env"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"activeProfiles"', r'"propertySources"', r'"systemProperties"']},
            ],
        }],
    },
    {
        "id": "spring-actuator-index",
        "info": {"name": "Spring Boot Actuator index exposed", "severity": "medium",
                  "tags": "exposure,spring,actuator,java"},
        "http": [{
            "method": "GET",
            "path": ["/actuator"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r'"_links"']},
            ],
        }],
    },
    {
        "id": "spring-actuator-beans",
        "info": {"name": "Spring Boot Actuator /beans endpoint exposed", "severity": "medium",
                  "tags": "exposure,spring,actuator,java"},
        "http": [{
            "method": "GET",
            "path": ["/actuator/beans"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r'"contexts"']},
            ],
        }],
    },
    {
        "id": "prometheus-metrics-exposure",
        "info": {"name": "Prometheus /metrics endpoint exposed", "severity": "medium",
                  "tags": "exposure,prometheus,monitoring"},
        "http": [{
            "method": "GET",
            "path": ["/metrics", "/actuator/prometheus"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?m)^# HELP ", r"(?m)^# TYPE "]},
            ],
        }],
    },
    {
        "id": "go-pprof-exposure",
        "info": {"name": "Go pprof debug endpoint exposed", "severity": "medium",
                  "tags": "exposure,golang,debug"},
        "http": [{
            "method": "GET",
            "path": ["/debug/pprof/", "/debug/pprof"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)goroutine", r"(?i)heap", r"(?i)pprof"]},
            ],
        }],
    },
    {
        "id": "symfony-profiler-exposure",
        "info": {"name": "Symfony debug/_profiler toolbar exposed", "severity": "high",
                  "tags": "exposure,symfony,php,debug"},
        "http": [{
            "method": "GET",
            "path": ["/_profiler", "/_profiler/empty/search/results",
                     "/_wdt/empty"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)symfony\s*profiler", r"(?i)sfwebdebug",
                            r"(?i)Symfony\s*Web\s*Debug"]},
            ],
        }],
    },
    {
        "id": "django-debug-toolbar",
        "info": {"name": "Django debug page / DEBUG=True disclosure", "severity": "high",
                  "tags": "exposure,django,python,debug"},
        "http": [{
            "method": "GET",
            # Requesting a guaranteed-nonexistent path triggers Django's debug
            # 404 page (when DEBUG=True), which includes framework details.
            # The /__debug__/ path is checked for the django-debug-toolbar.
            "path": ["/__debug__/", "/nonexistent-kArmasnuc-django-probe-xyz"],
            "matchers-condition": "or",
            "matchers": [
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)Django\s+Version", r"(?i)using\s+the\s+URLconf",
                            r"(?i)DJANGO_SETTINGS_MODULE", r"(?i)djdt"]},
            ],
        }],
    },
    {
        "id": "laravel-debug-exposure",
        "info": {"name": "Laravel debug mode / Ignition error page exposed", "severity": "high",
                  "tags": "exposure,laravel,php,debug"},
        "http": [{
            "method": "GET",
            "path": ["/nonexistent-kArmasnuc-laravel-probe-xyz",
                     "/_ignition/health-check"],
            "matchers-condition": "or",
            "matchers": [
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)laravel", r"(?i)Ignition",
                            r"(?i)illuminate\\\\", r"(?i)APP_DEBUG"]},
            ],
        }],
    },

    # ------------------------------------------------------------------ #
    # Environment / Config File Exposure
    # ------------------------------------------------------------------ #
    {
        "id": "env-variant-exposure",
        "info": {"name": "Exposed .env variant file (.env.local / .env.production / etc.)",
                  "severity": "critical", "tags": "exposure,config,secrets"},
        "http": [{
            "method": "GET",
            "path": ["/.env.local", "/.env.development", "/.env.staging",
                     "/.env.production", "/.env.prod", "/.env.dev",
                     "/.env.test", "/.env.backup", "/.env.example",
                     "/.env.sample"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r"(?i)[A-Z0-9_]+="]},
            ],
        }],
    },
    {
        "id": "application-yml-exposure",
        "info": {"name": "Exposed application.yml / application.properties (Spring config)",
                  "severity": "high", "tags": "exposure,config,spring,java"},
        "http": [{
            "method": "GET",
            "path": ["/application.yml", "/application.yaml",
                     "/application.properties", "/config/application.yml",
                     "/config/application.properties"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)spring\s*:", r"(?i)datasource", r"(?i)server\.port",
                            r"(?i)management\.endpoints"]},
            ],
        }],
    },
    {
        "id": "database-yml-exposure",
        "info": {"name": "Exposed database.yml (Rails DB credentials)", "severity": "critical",
                  "tags": "exposure,config,rails,ruby,secrets"},
        "http": [{
            "method": "GET",
            "path": ["/config/database.yml", "/database.yml"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)adapter:\s*(mysql|postgres|sqlite)",
                            r"(?i)password:\s*\S+", r"(?i)database:\s*\S+"]},
            ],
        }],
    },
    {
        "id": "web-config-exposure",
        "info": {"name": "Exposed web.config / backup", "severity": "high",
                  "tags": "exposure,config,iis,dotnet"},
        "http": [{
            "method": "GET",
            "path": ["/web.config", "/web.config.bak", "/web.config.old",
                     "/web.config~"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["<configuration>", "<connectionStrings>",
                            "<appSettings>", "<system.web>"]},
            ],
        }],
    },
    {
        "id": "nginx-config-exposure",
        "info": {"name": "Exposed nginx.conf or httpd.conf", "severity": "medium",
                  "tags": "exposure,config,nginx,apache"},
        "http": [{
            "method": "GET",
            "path": ["/nginx.conf", "/conf/nginx.conf", "/httpd.conf",
                     "/.nginx.conf"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)server\s*\{", r"(?i)listen\s+\d+",
                            r"(?i)DocumentRoot", r"(?i)VirtualHost"]},
            ],
        }],
    },
    {
        "id": "settings-py-exposure",
        "info": {"name": "Exposed settings.py (Django settings)", "severity": "critical",
                  "tags": "exposure,config,django,python,secrets"},
        "http": [{
            "method": "GET",
            "path": ["/settings.py", "/config/settings.py",
                     "/app/settings.py"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)SECRET_KEY\s*=", r"(?i)DATABASES\s*=",
                            r"(?i)INSTALLED_APPS\s*="]},
            ],
        }],
    },

    # ------------------------------------------------------------------ #
    # Cloud / Storage Config Leakage
    # ------------------------------------------------------------------ #
    {
        "id": "aws-credentials-exposure",
        "info": {"name": "Exposed AWS credentials file", "severity": "critical",
                  "tags": "exposure,cloud,aws,secrets"},
        "http": [{
            "method": "GET",
            "path": ["/.aws/credentials", "/aws/credentials",
                     "/.aws/config"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)aws_access_key_id",
                            r"(?i)aws_secret_access_key",
                            r"(?i)\[default\]"]},
            ],
        }],
    },
    {
        "id": "npmrc-exposure",
        "info": {"name": "Exposed .npmrc (npm auth token / registry config)", "severity": "high",
                  "tags": "exposure,nodejs,secrets,npm"},
        "http": [{
            "method": "GET",
            "path": ["/.npmrc"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)_authToken", r"(?i)registry\s*=",
                            r"(?i)_auth\s*="]},
            ],
        }],
    },
    {
        "id": "docker-config-exposure",
        "info": {"name": "Exposed Docker config.json (registry credentials)", "severity": "critical",
                  "tags": "exposure,docker,secrets"},
        "http": [{
            "method": "GET",
            "path": ["/.docker/config.json"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ['"auths"', '"HttpHeaders"', '"credsStore"']},
            ],
        }],
    },
    {
        "id": "s3cfg-exposure",
        "info": {"name": "Exposed .s3cfg (S3 access keys)", "severity": "critical",
                  "tags": "exposure,cloud,aws,secrets"},
        "http": [{
            "method": "GET",
            "path": ["/.s3cfg"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)access_key\s*=", r"(?i)secret_key\s*=",
                            r"(?i)\[default\]"]},
            ],
        }],
    },
    {
        "id": "gcloud-credentials-exposure",
        "info": {"name": "Exposed Google Cloud credentials JSON", "severity": "critical",
                  "tags": "exposure,cloud,gcp,secrets"},
        "http": [{
            "method": "GET",
            "path": ["/.config/gcloud/credentials.db",
                     "/gcloud-credentials.json",
                     "/google-credentials.json"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"type":\s*"service_account"',
                            r'"client_email":', r'"private_key":']},
            ],
        }],
    },

    # ------------------------------------------------------------------ #
    # Installer / Setup Leftovers
    # ------------------------------------------------------------------ #
    {
        "id": "install-php-exposure",
        "info": {"name": "Exposed install.php / setup.php (CMS installer)", "severity": "high",
                  "tags": "exposure,misconfig,installer"},
        "http": [{
            "method": "GET",
            "path": ["/install.php", "/setup.php", "/install/index.php",
                     "/admin/install.php", "/wp-admin/install.php",
                     "/cms/install.php"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)installation", r"(?i)installer",
                            r"(?i)database setup", r"(?i)welcome to"]},
            ],
        }],
    },
    {
        "id": "dockerfile-exposure",
        "info": {"name": "Exposed Dockerfile", "severity": "medium",
                  "tags": "exposure,docker,misconfig"},
        "http": [{
            "method": "GET",
            "path": ["/Dockerfile", "/.Dockerfile"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?m)^FROM\s+\S+", r"(?m)^RUN\s+",
                            r"(?m)^COPY\s+"]},
            ],
        }],
    },
    {
        "id": "docker-compose-exposure",
        "info": {"name": "Exposed docker-compose.yml (service/secret disclosure)", "severity": "high",
                  "tags": "exposure,docker,misconfig,secrets"},
        "http": [{
            "method": "GET",
            "path": ["/docker-compose.yml", "/docker-compose.yaml",
                     "/docker-compose.prod.yml",
                     "/docker-compose.production.yml"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)services\s*:", r"(?i)image\s*:\s*\S+",
                            r"(?i)environment\s*:"]},
            ],
        }],
    },
    {
        "id": "ansible-playbook-exposure",
        "info": {"name": "Exposed Ansible playbook / inventory file", "severity": "high",
                  "tags": "exposure,ansible,devops,secrets"},
        "http": [{
            "method": "GET",
            "path": ["/playbook.yml", "/site.yml", "/inventory",
                     "/hosts", "/ansible.cfg"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)hosts\s*:", r"(?i)become\s*:",
                            r"(?i)\[all\]", r"(?i)ansible_"]},
            ],
        }],
    },
    {
        "id": "makefile-exposure",
        "info": {"name": "Exposed Makefile (build target disclosure)", "severity": "low",
                  "tags": "exposure,misconfig"},
        "http": [{
            "method": "GET",
            "path": ["/Makefile", "/makefile"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r"(?m)^\w[\w\-]+\s*:"]},
            ],
        }],
    },

    # ------------------------------------------------------------------ #
    # Missing Security Headers
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
        "id": "missing-x-content-type-options",
        "info": {"name": "Missing X-Content-Type-Options header", "severity": "low",
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
        "id": "missing-permissions-policy",
        "info": {"name": "Missing Permissions-Policy header", "severity": "low",
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

    # ------------------------------------------------------------------ #
    # Service Panels and Dashboards
    # ------------------------------------------------------------------ #
    {
        "id": "phpmyadmin-exposure",
        "info": {"name": "phpMyAdmin panel exposed", "severity": "high",
                  "tags": "exposure,panel,database,php"},
        "http": [{
            "method": "GET",
            "path": ["/phpmyadmin/", "/pma/", "/phpMyAdmin/",
                     "/phpmyadmin/index.php"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)phpMyAdmin", r"(?i)pma_username",
                            r"(?i)Welcome to phpMyAdmin"]},
            ],
        }],
    },
    {
        "id": "adminer-exposure",
        "info": {"name": "Adminer database panel exposed", "severity": "high",
                  "tags": "exposure,panel,database,php"},
        "http": [{
            "method": "GET",
            "path": ["/adminer.php", "/adminer/", "/db.php",
                     "/database.php"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)adminer", r"(?i)Login\s+–\s+Adminer"]},
            ],
        }],
    },
    {
        "id": "kibana-exposure",
        "info": {"name": "Kibana dashboard exposed", "severity": "medium",
                  "tags": "exposure,panel,kibana,elastic"},
        "http": [{
            "method": "GET",
            "path": ["/app/kibana", "/app/kibana#/",
                     "/kibana/", "/_plugin/kibana/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)kibana", r"(?i)elastic"]},
            ],
        }],
    },
    {
        "id": "grafana-exposure",
        "info": {"name": "Grafana dashboard exposed", "severity": "medium",
                  "tags": "exposure,panel,grafana,monitoring"},
        "http": [{
            "method": "GET",
            "path": ["/grafana/", "/grafana/login"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)grafana", r"(?i)Grafana Labs"]},
            ],
        }],
    },
    {
        "id": "jenkins-exposure",
        "info": {"name": "Jenkins CI/CD dashboard exposed", "severity": "high",
                  "tags": "exposure,panel,jenkins,cicd"},
        "http": [{
            "method": "GET",
            "path": ["/jenkins/", "/jenkins/login", "/login?from=%2F"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)jenkins", r"(?i)hudson"]},
            ],
        }],
    },
    {
        "id": "jupyter-notebook-exposure",
        "info": {"name": "Jupyter Notebook server exposed", "severity": "critical",
                  "tags": "exposure,panel,jupyter,python"},
        "http": [{
            "method": "GET",
            "path": ["/tree", "/notebooks/", "/lab"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)jupyter", r"(?i)ipython\s*notebook",
                            r"(?i)JupyterLab"]},
            ],
        }],
    },
    {
        "id": "elasticsearch-api-exposure",
        "info": {"name": "Elasticsearch API exposed", "severity": "high",
                  "tags": "exposure,panel,elasticsearch,database"},
        "http": [{
            "method": "GET",
            "path": ["/_cat/indices", "/_cluster/health", "/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"cluster_name"', r'"tagline"\s*:\s*"You Know, for Search"',
                            r'"number_of_nodes"']},
            ],
        }],
    },
    {
        "id": "redis-commander-exposure",
        "info": {"name": "Redis Commander panel exposed", "severity": "high",
                  "tags": "exposure,panel,redis,database"},
        "http": [{
            "method": "GET",
            "path": ["/redis-commander/", "/redis/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r"(?i)redis\s*commander"]},
            ],
        }],
    },
    {
        "id": "rancher-exposure",
        "info": {"name": "Rancher Kubernetes management UI exposed", "severity": "high",
                  "tags": "exposure,panel,rancher,kubernetes"},
        "http": [{
            "method": "GET",
            "path": ["/dashboard/", "/dashboard/auth/login"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r"(?i)rancher"]},
            ],
        }],
    },
    {
        "id": "traefik-dashboard-exposure",
        "info": {"name": "Traefik reverse proxy dashboard exposed", "severity": "medium",
                  "tags": "exposure,panel,traefik"},
        "http": [{
            "method": "GET",
            "path": ["/dashboard/", "/api/rawdata", "/api/overview"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)traefik", r'"routers"', r'"services"']},
            ],
        }],
    },

    # ------------------------------------------------------------------ #
    # Well-known / Metadata Exposure
    # ------------------------------------------------------------------ #
    {
        "id": "security-txt-exposure",
        "info": {"name": "security.txt present (informational)", "severity": "info",
                  "tags": "exposure,disclosure,wellknown"},
        "http": [{
            "method": "GET",
            "path": ["/.well-known/security.txt", "/security.txt"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)Contact:\s*", r"(?i)Expires:\s*"]},
            ],
        }],
    },
    {
        "id": "crossdomain-xml-exposure",
        "info": {"name": "Permissive crossdomain.xml (Flash/Silverlight)", "severity": "medium",
                  "tags": "exposure,misconfig,cors"},
        "http": [{
            "method": "GET",
            "path": ["/crossdomain.xml"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r'domain\s*=\s*["\']?\*["\']?']},
            ],
        }],
    },
    {
        "id": "clientaccesspolicy-exposure",
        "info": {"name": "Permissive clientaccesspolicy.xml (Silverlight)", "severity": "medium",
                  "tags": "exposure,misconfig,cors"},
        "http": [{
            "method": "GET",
            "path": ["/clientaccesspolicy.xml"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r'uri\s*=\s*["\']?\*["\']?']},
            ],
        }],
    },

    # ------------------------------------------------------------------ #
    # Robots / Sitemap Disclosure
    # ------------------------------------------------------------------ #
    {
        "id": "robots-txt-sensitive-paths",
        "info": {"name": "robots.txt discloses sensitive path patterns", "severity": "low",
                  "tags": "exposure,disclosure,robots"},
        "http": [{
            "method": "GET",
            "path": ["/robots.txt"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)Disallow:\s*/admin", r"(?i)Disallow:\s*/api",
                            r"(?i)Disallow:\s*/backup", r"(?i)Disallow:\s*/config",
                            r"(?i)Disallow:\s*/internal", r"(?i)Disallow:\s*/secret",
                            r"(?i)Disallow:\s*/private"]},
            ],
            "extractors": [
                {"regex": [r"(?i)Disallow:\s*(\S+)"]},
            ],
        }],
    },
    {
        "id": "sitemap-xml-exposure",
        "info": {"name": "sitemap.xml present (URL enumeration aid)", "severity": "info",
                  "tags": "exposure,disclosure,sitemap"},
        "http": [{
            "method": "GET",
            "path": ["/sitemap.xml", "/sitemap_index.xml"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["<urlset", "<sitemapindex"]},
            ],
        }],
    },

    # ------------------------------------------------------------------ #
    # Additional Backup / Config Suffixes
    # ------------------------------------------------------------------ #
    {
        "id": "htpasswd-exposure",
        "info": {"name": "Exposed .htpasswd file", "severity": "critical",
                  "tags": "exposure,apache,secrets,credentials"},
        "http": [{
            "method": "GET",
            "path": ["/.htpasswd", "/.htpasswd.bak"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r"(?m)^\w[\w.\-@]+:\$\S+"]},
            ],
        }],
    },
    {
        "id": "htaccess-exposure",
        "info": {"name": "Exposed .htaccess file (config disclosure)", "severity": "medium",
                  "tags": "exposure,apache,config"},
        "http": [{
            "method": "GET",
            "path": ["/.htaccess", "/.htaccess.bak"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)RewriteRule", r"(?i)RewriteEngine",
                            r"(?i)AuthType", r"(?i)Options\s"]},
            ],
        }],
    },
    {
        "id": "editorconfig-exposure",
        "info": {"name": "Exposed .editorconfig (minor metadata disclosure)", "severity": "info",
                  "tags": "exposure,misconfig"},
        "http": [{
            "method": "GET",
            "path": ["/.editorconfig"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["root = true", "[*]", "indent_style"]},
            ],
        }],
    },
    {
        "id": "ssh-private-key-exposure",
        "info": {"name": "Exposed SSH private key", "severity": "critical",
                  "tags": "exposure,secrets,ssh"},
        "http": [{
            "method": "GET",
            "path": ["/.ssh/id_rsa", "/.ssh/id_dsa", "/.ssh/id_ecdsa",
                     "/.ssh/id_ed25519", "/id_rsa", "/id_rsa.pub"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r"(?i)BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE KEY"]},
            ],
        }],
    },
    {
        "id": "extra-backup-files",
        "info": {"name": "Exposed additional backup / temp file", "severity": "medium",
                  "tags": "exposure,backup,misconfig"},
        "http": [{
            "method": "GET",
            "path": ["/backup.bak", "/www.tar.gz", "/site.tar.gz",
                     "/web.zip", "/public_html.zip", "/files.zip",
                     "/db.sql.gz", "/dump.sql.gz", "/config.bak",
                     "/config.old", "/config.orig"],
            # Send a Range header to avoid downloading the full archive body.
            # Detection is based on Content-Type so we only need the response headers.
            "headers": {"Range": "bytes=0-0"},
            "matchers-condition": "or",
            "matchers": [
                # Binary archives return octet-stream; SQL dumps are text/plain.
                # Use content-type as a positive signal rather than a fragile
                # negative HTML-title check.
                {"type": "regex", "part": "header",
                 "regex": [r"(?i)Content-Type:\s*(application/(octet-stream|zip|x-gzip|x-tar|gzip|sql)|text/plain)"]},
            ],
        }],
    },

    # ------------------------------------------------------------------ #
    # Framework / Next.js / Vite Build Artifact Exposure
    {
        "id": "nextjs-build-manifest-exposure",
        "info": {"name": "Exposed Next.js build-manifest.json", "severity": "low",
                  "tags": "exposure,nextjs,nodejs"},
        "http": [{
            "method": "GET",
            "path": ["/_next/static/chunks/pages/_app.js",
                     "/_next/build-manifest.json",
                     "/_next/static/development/_buildManifest.js"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"pages"', r'__BUILD_MANIFEST', r'_buildManifest']},
            ],
        }],
    },
    {
        "id": "vite-config-exposure",
        "info": {"name": "Exposed Vite / Webpack source map or config", "severity": "medium",
                  "tags": "exposure,vite,webpack,nodejs"},
        "http": [{
            "method": "GET",
            "path": ["/vite.config.js", "/vite.config.ts",
                     "/webpack.config.js", "/webpack.config.ts"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)defineConfig", r"(?i)module\.exports\s*=",
                            r"(?i)entry\s*:", r"(?i)output\s*:"]},
            ],
        }],
    },
    {
        "id": "js-source-map-exposure",
        "info": {"name": "JavaScript source map (.map) publicly accessible", "severity": "medium",
                  "tags": "exposure,sourcemap,nodejs"},
        "http": [{
            "method": "GET",
            "path": ["/static/js/main.chunk.js.map",
                     "/assets/app.js.map",
                     "/js/app.js.map",
                     "/dist/bundle.js.map"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body",
                 "regex": [r'"sources"\s*:\s*\[']},
            ],
        }],
    },

    # ------------------------------------------------------------------ #
    # Miscellaneous / Additional
    # ------------------------------------------------------------------ #
    {
        "id": "wp-debug-log-exposure",
        "info": {"name": "Exposed WordPress debug.log", "severity": "medium",
                  "tags": "exposure,wordpress,debug"},
        "http": [{
            "method": "GET",
            "path": ["/wp-content/debug.log"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)PHP\s+(Fatal|Warning|Notice|Error)",
                            r"(?i)\[.*\]\s+PHP"]},
            ],
        }],
    },
    {
        "id": "laravel-log-exposure",
        "info": {"name": "Exposed Laravel / application log file", "severity": "medium",
                  "tags": "exposure,laravel,php,debug"},
        "http": [{
            "method": "GET",
            "path": ["/storage/logs/laravel.log",
                     "/app/storage/logs/laravel.log"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)\[20\d\d-\d\d-\d\d",
                            r"(?i)local\.ERROR", r"(?i)production\.ERROR"]},
            ],
        }],
    },
    {
        "id": "git-directory-listing",
        "info": {"name": "Exposed .git/ directory index (full repo accessible)", "severity": "critical",
                  "tags": "exposure,git,vcs"},
        "http": [{
            "method": "GET",
            "path": ["/.git/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 # Match actual directory listing entries for git repository files
                 "regex": [r'(?i)Index of /.git',
                            r'(?i)<a href="HEAD">',
                            r'(?i)<a href="COMMIT_EDITMSG">',
                            r'(?i)<a href="config">']},
            ],
        }],
    },
    {
        "id": "phpunit-test-file-exposure",
        "info": {"name": "Exposed phpunit test / eval-stdin file (RCE risk)", "severity": "critical",
                  "tags": "exposure,php,debug"},
        "http": [{
            "method": "GET",
            "path": ["/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                     "/laravel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                # Soft-404 pages return full HTML; the real eval-stdin.php either
                # executes (empty body) or is served as plain PHP source. Exclude
                # responses that look like HTML error pages to avoid false positives.
                {"type": "regex", "part": "body", "negative": True,
                 "regex": [r"(?i)<!DOCTYPE\s+html|<html\b"]},
            ],
        }],
    },
    {
        "id": "xml-rpc-enabled",
        "info": {"name": "WordPress XML-RPC enabled (amplification / brute-force vector)",
                  "severity": "medium", "tags": "exposure,wordpress,misconfig"},
        "http": [{
            "method": "GET",
            "path": ["/xmlrpc.php"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200, 405]},
                {"type": "word", "part": "body", "condition": "or",
                 "words": ["XML-RPC server accepts POST requests only",
                            "xmlrpc"]},
            ],
        }],
    },
    {
        "id": "exposed-readme-version",
        "info": {"name": "CMS/Framework README exposes version", "severity": "info",
                  "tags": "exposure,fingerprint,disclosure"},
        "http": [{
            "method": "GET",
            "path": ["/README.md", "/README.txt", "/readme.html",
                     "/readme.txt", "/CHANGELOG.md", "/CHANGELOG.txt"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?i)version\s+\d+\.\d+", r"(?i)wordpress\s+\d+\.\d+",
                            r"(?i)joomla\s+\d+\.\d+", r"(?i)drupal\s+\d+\.\d+"]},
            ],
        }],
    },

    # ------------------------------------------------------------------ #
    # OSINT / Reconnaissance Templates
    # ------------------------------------------------------------------ #
    {
=======
>>>>>>> origin/main
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
                     r"""(?i)['"]?api[_-]?key['"]?\s*:\s*['"](?!test|xxxx|changeme|sample|demo)[^'"]{8,}['"]""",
                     r"""(?i)['"]?client[_-]?secret['"]?\s*:\s*['"](?!test|xxxx|changeme|sample|demo)[^'"]{8,}['"]""",
                     r"""(?i)['"]?jwt[_-]?secret['"]?\s*:\s*['"](?!test|xxxx|changeme|sample|demo)[^'"]{8,}['"]""",
                     r"""(?i)['"]?db[_-]?password['"]?\s*:\s*['"](?!test|xxxx|changeme|sample|demo)[^'"]{8,}['"]""",
                     r"""(?i)['"]?access[_-]?key[_-]?id['"]?\s*:\s*['"](?!test|xxxx|changeme|sample|demo)[^'"]{8,}['"]""",
                 ]},
            ],
        }],
    },
    {
<<<<<<< HEAD
=======
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
>>>>>>> origin/main
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
        "info": {"name": "Apple app site association discovered", "severity": "info",
                  "tags": "osint,recon,mobile,ios,well-known"},
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
        "info": {"name": "OpenID configuration metadata discovered", "severity": "low",
                  "tags": "osint,recon,openid,oauth,api,well-known"},
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
        "info": {"name": "OAuth authorization server metadata discovered", "severity": "low",
                  "tags": "osint,recon,oauth,api,well-known"},
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
<<<<<<< HEAD
=======
        "id": "package-json-exposure",
        "info": {"name": "Public package.json metadata", "severity": "info", "tags": "osint,recon,metadata,nodejs"},
        "http": [{
            "method": "GET",
            "path": ["/package.json"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r'"name"\s*:', r'"version"\s*:', r'"dependencies"\s*:']},
            ],
        }],
    },
    {
>>>>>>> origin/main
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
<<<<<<< HEAD
=======
        "id": "yarn-lock-exposure",
        "info": {"name": "Public yarn.lock metadata", "severity": "info", "tags": "osint,recon,metadata,nodejs"},
        "http": [{
            "method": "GET",
            "path": ["/yarn.lock"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "condition": "or",
                 "regex": [r"(?m)^# yarn lockfile", r'(?m)^"?[^"\n]+@[^:\n]+:\s*$']},
            ],
        }],
    },
    {
>>>>>>> origin/main
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
                 "regex": [r"(?i)\b(healthy|ok|pass)\b", r"(?i)\"status\"\s*:"]},
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
