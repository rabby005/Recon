import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List
from urllib.parse import urlparse

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

# ─── Sensitive File/Path List ──────────────────────────────────────────────────
SENSITIVE_PATHS = [
    # Environment & Config
    ("/.env",                    "HIGH",   "Environment variables file"),
    ("/.env.local",              "HIGH",   "Local environment file"),
    ("/.env.production",         "HIGH",   "Production environment file"),
    ("/.env.backup",             "HIGH",   "Backup environment file"),
    ("/config.php",              "HIGH",   "PHP config file"),
    ("/config.yml",              "HIGH",   "YAML config file"),
    ("/config.json",             "HIGH",   "JSON config file"),
    ("/configuration.php",       "HIGH",   "PHP configuration file"),
    ("/wp-config.php",           "HIGH",   "WordPress config file"),
    ("/database.yml",            "HIGH",   "Database config file"),
    ("/settings.py",             "HIGH",   "Python settings file"),
    ("/local_settings.py",       "HIGH",   "Local Python settings"),
    ("/appsettings.json",        "HIGH",   ".NET app settings"),

    # Backup Files
    ("/backup.zip",              "HIGH",   "Backup archive"),
    ("/backup.tar.gz",           "HIGH",   "Backup tarball"),
    ("/backup.sql",              "HIGH",   "Database backup"),
    ("/db.sql",                  "HIGH",   "Database dump"),
    ("/dump.sql",                "HIGH",   "SQL dump file"),
    ("/site.zip",                "HIGH",   "Site archive"),
    ("/www.zip",                 "HIGH",   "Web root archive"),

    # Git & Version Control
    ("/.git/config",             "HIGH",   "Git config exposed"),
    ("/.git/HEAD",               "HIGH",   "Git HEAD file exposed"),
    ("/.gitignore",              "MEDIUM", "Git ignore file"),
    ("/.svn/entries",            "HIGH",   "SVN repository exposed"),

    # Log Files
    ("/error.log",               "MEDIUM", "Error log file"),
    ("/access.log",              "MEDIUM", "Access log file"),
    ("/debug.log",               "MEDIUM", "Debug log file"),
    ("/app.log",                 "MEDIUM", "Application log file"),
    ("/laravel.log",             "MEDIUM", "Laravel log file"),
    ("/storage/logs/laravel.log","MEDIUM", "Laravel storage log"),

    # Admin & Sensitive Pages
    ("/admin",                   "MEDIUM", "Admin panel"),
    ("/admin/",                  "MEDIUM", "Admin panel"),
    ("/phpmyadmin",              "HIGH",   "phpMyAdmin exposed"),
    ("/phpmyadmin/",             "HIGH",   "phpMyAdmin exposed"),
    ("/adminer.php",             "HIGH",   "Adminer DB tool exposed"),

    # Info & Debug Files
    ("/phpinfo.php",             "HIGH",   "PHP info page exposed"),
    ("/info.php",                "HIGH",   "PHP info page"),
    ("/test.php",                "MEDIUM", "Test PHP file"),
    ("/readme.txt",              "LOW",    "Readme file"),
    ("/README.md",               "LOW",    "Readme file"),
    ("/CHANGELOG.md",            "LOW",    "Changelog exposed"),
    ("/robots.txt",              "LOW",    "Robots.txt (check for hidden paths)"),
    ("/sitemap.xml",             "LOW",    "Sitemap exposed"),

    # Package & Dependency Files
    ("/composer.json",           "MEDIUM", "PHP composer config"),
    ("/composer.lock",           "MEDIUM", "PHP composer lockfile"),
    ("/package.json",            "MEDIUM", "Node.js package config"),
    ("/package-lock.json",       "MEDIUM", "Node.js lockfile"),
    ("/requirements.txt",        "MEDIUM", "Python requirements"),
    ("/Gemfile",                 "MEDIUM", "Ruby Gemfile"),
    ("/Gemfile.lock",            "MEDIUM", "Ruby Gemfile lock"),

    # Server Config
    ("/.htaccess",               "MEDIUM", "Apache htaccess file"),
    ("/web.config",              "MEDIUM", "IIS web config"),
    ("/nginx.conf",              "HIGH",   "Nginx config exposed"),

    # SSH & Keys
    ("/.ssh/id_rsa",             "HIGH",   "SSH private key exposed"),
    ("/.ssh/authorized_keys",    "HIGH",   "SSH authorized keys"),
    ("/id_rsa",                  "HIGH",   "SSH private key"),
    ("/server.key",              "HIGH",   "SSL private key"),
]

EXPOSED_INDICATORS = [
    "DB_PASSWORD", "DB_HOST", "SECRET_KEY", "API_KEY", "AWS_SECRET",
    "root:", "mysql:", "[mysqld]", "password =", "passwd",
    "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----",
    "[core]", "repositoryformatversion",
]


def check_single(
    base_url: str,
    path: str,
    severity: str,
    description: str,
    headers: Dict[str, str],
    cookies: Dict[str, str],
    timeout: int,
) -> Dict:
    url = base_url.rstrip("/") + path
    try:
        resp = requests.get(
            url,
            headers=headers,
            cookies=cookies,
            timeout=timeout,
            allow_redirects=False,
            verify=False,
        )

        if resp.status_code in (200, 206):
            content = resp.text[:500]
            # Sensitive content indicator check
            found_indicators = [ind for ind in EXPOSED_INDICATORS if ind.lower() in content.lower()]
            confirmed = len(found_indicators) > 0

            return {
                "url":         url,
                "status_code": resp.status_code,
                "severity":    "HIGH" if confirmed else severity,
                "description": description,
                "confirmed":   confirmed,
                "indicators":  found_indicators,
                "content_preview": content[:200],
                "exposed":     True,
            }

        return {"url": url, "exposed": False, "status_code": resp.status_code}

    except Exception as e:
        return {"url": url, "exposed": False, "error": str(e)}


def check_sensitive_files(
    subdomains: List[str],
    headers: Dict[str, str],
    cookies: Dict[str, str],
    timeout: int = 10,
    rate_limit: float = 0.3,
    concurrency: int = 5,
) -> List[Dict]:
    """
    সব subdomains এ sensitive file check করো।
    শুধু exposed (status 200) গুলো return করো।
    """
    tasks = []
    for subdomain in subdomains:
        base = subdomain if subdomain.startswith("http") else f"https://{subdomain}"
        for path, severity, description in SENSITIVE_PATHS:
            tasks.append((base, path, severity, description))

    results = []
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {
            executor.submit(
                check_single, base, path, severity, desc, headers, cookies, timeout
            ): (base, path)
            for base, path, severity, desc in tasks
        }
        for future in as_completed(futures):
            result = future.result()
            if result.get("exposed"):
                results.append(result)
            time.sleep(rate_limit / concurrency)

    return results
