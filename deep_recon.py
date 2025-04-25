import requests
import re
import ssl
import socket
import subprocess
import os
import time
from urllib.parse import urlparse

# Try to import Shodan, but don’t crash if it’s missing
try:
    from shodan import Shodan
    SHODAN_ENABLED = True
except ImportError:
    SHODAN_ENABLED = False

# === API Keys ===
SHODAN_API_KEY = ""    # Placeholder for future Shodan integration
VT_API_KEY = ""        # Placeholder for future VT integration

def extract_emails(html):
    return re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", html)

def extract_inputs(html):
    return re.findall(r"<input[^>]*name=[\"']?([^\"'> ]+)", html, re.IGNORECASE)

def extract_iframes(html):
    return re.findall(r"<iframe[^>]+(?:src|data-src)=['\"]?([^\"'>]+)", html, re.IGNORECASE)

def extract_scripts(html, domain):
    scripts = re.findall(r"<script[^>]+src=['\"]?([^\"'>]+)", html, re.IGNORECASE)
    return [s for s in scripts if domain not in s]

def get_ssl_info(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            return s.getpeercert()
    except Exception as e:
        return f"[!] SSL Error: {e}"

def run_deep_recon(target_url):
    if not target_url.startswith("http"):
        target_url = "https://" + target_url

    parsed = urlparse(target_url)
    base_domain = parsed.netloc or parsed.path
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    report_path = f"reports/{base_domain}_deeprecon_{timestamp}.txt"
    os.makedirs("reports", exist_ok=True)

    def log(line):
        print(line)
        with open(report_path, "a") as report:
            report.write(line + "\n")

    log(f"\n🕷 Deep Recon on: {target_url}\n")

    log("🔀 Redirects (via curl -L -I):")
    try:
        result = subprocess.check_output(["curl", "-s", "-L", "-I", target_url], timeout=15).decode()
        for line in result.strip().split("\n"):
            if line.lower().startswith(("http", "location", "server", "status", "content-type")):
                log(line.strip())
    except Exception as e:
        log(f"[!] Redirect trace failed: {e}")

    log("\n📜 SSL Certificate Info:")
    ssl_info = get_ssl_info(base_domain)
    log(str(ssl_info))

    log("\n📜 OpenSSL x509 Full Cert Dump:")
    try:
        openssl_dump = subprocess.check_output(
            f"echo | openssl s_client -connect {base_domain}:443 2>/dev/null | openssl x509 -noout -text",
            shell=True, timeout=15
        ).decode()
        for line in openssl_dump.strip().split("\n"):
            log(line.strip())
    except Exception as e:
        log(f"[!] OpenSSL cert dump failed: {e}")

    try:
        response = requests.get(target_url, timeout=15, headers={'User-Agent': 'Mozilla/5.0'})
        html = response.text
    except Exception as e:
        log(f"[!] Failed to fetch HTML: {e}")
        return

    html_path = f"reports/{base_domain}_{timestamp}.html"
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)
    log(f"\n🗂 HTML snapshot saved to: {html_path}")

    log("\n🧾 Input Fields:")
    for i in extract_inputs(html) or ["- None"]:
        log(f"- {i}")

    log("\n🪞 Iframes Found:")
    for iframe in extract_iframes(html) or ["- None"]:
        log(f"- {iframe}")

    log("\n📧 Emails Found:")
    for email in extract_emails(html) or ["- None"]:
        log(f"- {email}")

    log("\n📦 External Scripts:")
    for script in extract_scripts(html, base_domain) or ["- None"]:
        log(f"- {script}")

    log("\n📎 Meta Tags:")
    for meta in re.findall(r"<meta[^>]+>", html, re.IGNORECASE) or ["- None"]:
        log(f"- {meta}")

    log("\n🕵️‍♀️ Form Discovery (via curl grep):")
    try:
        grep_out = subprocess.check_output(
            f"curl -s {target_url} | grep -iE '(form|action|input)' || true",
            shell=True, timeout=15
        ).decode()
        if grep_out.strip():
            for line in grep_out.strip().split("\n"):
                log(line.strip())
        else:
            log("- No forms found")
    except Exception as e:
        log(f"[!] Curl grep failed: {e}")

    log("\n📥 Raw HTML Copy (curl -o):")
    try:
        raw_path = f"reports/raw_{base_domain}_{timestamp}.html"
        subprocess.run(["curl", "-s", target_url, "-o", raw_path], timeout=15)
        log(f"Saved raw HTML to {raw_path}")
    except Exception as e:
        log(f"[!] Raw HTML save failed: {e}")

    log("\n📡 Nmap Scan (Top 1000 ports):")
    try:
        ip = socket.gethostbyname(base_domain)
        log(f"[DEBUG] Resolved IP: {ip}")
        nmap_result = subprocess.check_output(
            ["nmap", "-sV", "--top-ports", "1000", ip],
            timeout=240
        ).decode()
        for line in nmap_result.strip().split("\n"):
            log(line)
    except Exception as e:
        log(f"[!] Nmap scan failed: {e}")

    log("\n🛰 Shodan Recon:")
    if SHODAN_ENABLED:
        try:
            ip = socket.gethostbyname(base_domain)
            api = Shodan(SHODAN_API_KEY)
            data = api.host(ip)
            log(f"IP: {data.get('ip_str', 'N/A')}")
            log(f"Org: {data.get('org', 'N/A')}")
            log(f"ISP: {data.get('isp', 'N/A')}")
            log(f"Hostnames: {', '.join(data.get('hostnames', []))}")
            log(f"Ports: {', '.join(map(str, data.get('ports', [])))}")
        except Exception as e:
            if "403" in str(e):
                log("[!] Shodan API returned 403 – check free tier limits or upgrade")
            else:
                log(f"[!] Shodan lookup failed: {e}")
    else:
        log("[!] Shodan module not installed. Skipping Shodan scan.")
        log("    → To enable it, install with: sudo apt install python3-pip && pip3 install shodan (optional)")

    log("\n📂 DIRB Scan (/usr/share/dirb/wordlists/common.txt):")
    try:
        dirb_result = subprocess.check_output(
            ["dirb", target_url, "/usr/share/dirb/wordlists/common.txt", "-f"],
            stderr=subprocess.DEVNULL,
            timeout=600
        ).decode()
        for line in dirb_result.splitlines():
            if "==>" in line or "CODE:" in line:
                log(line)
    except Exception as e:
        log(f"[!] DIRB scan failed: {e}")

    log("\n🕷 Deep Recon Complete.\n")
