import requests
import re
import ssl
import socket
import subprocess
import os
import time
import base64
from urllib.parse import urlparse, urljoin

# Try to import Shodan, but don’t crash if it’s missing
try:
    from shodan import Shodan
    SHODAN_ENABLED = True
except ImportError:
    SHODAN_ENABLED = False

# === API Keys ===
SHODAN_API_KEY = ""    # Placeholder for your Shodan api
VT_API_KEY = ""        # Placeholder for future VT api

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

def decode_base64_target(text):
    matches = re.findall(r"target=([A-Za-z0-9+/=]+)", text)
    decoded_targets = []
    for encoded in matches:
        try:
            decoded = base64.b64decode(encoded).decode('utf-8')
            decoded_targets.append(decoded)
        except Exception:
            continue
    return decoded_targets

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

    log(f"\nDeep Recon on: {target_url}\n")

    log("Redirects (via curl -L -I):")
    try:
        result = subprocess.check_output(["curl", "-s", "-L", "-I", target_url], timeout=15).decode()
        for line in result.strip().split("\n"):
            if line.lower().startswith(("http", "location", "server", "status", "content-type")):
                log(line.strip())
    except Exception as e:
        log(f"[!] Redirect trace failed: {e}")

    meta_redirects = []
    visited = set()
    current_url = target_url
    final_html = ""

    log("\nFollowing Meta-Refresh Redirects:")

    while current_url and current_url not in visited:
        visited.add(current_url)
        log(f"Visiting: {current_url}")

        try:
            response = requests.get(current_url, timeout=15, headers={'User-Agent': 'Mozilla/5.0'})
            html = response.text
            final_html = html

            parsed_current = urlparse(current_url)
            safe_filename = parsed_current.netloc.replace(".", "_") + parsed_current.path.replace("/", "_")
            safe_filename = safe_filename.strip("_")
            if safe_filename:
                page_path = f"reports/{safe_filename}_{timestamp}.html"
                with open(page_path, "w", encoding="utf-8") as f:
                    f.write(html)
                log(f"Saved page snapshot: {page_path}")

            decoded_targets_url = decode_base64_target(current_url)
            for decoded in decoded_targets_url:
                log(f"  Decoded target from URL: {decoded}")

        except Exception as e:
            log(f"[!] Failed to fetch {current_url}: {e}")
            break

        try:
            meta_refreshes = re.findall(
                r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?\d+;\s*URL=(.*?)["\'>]',
                html,
                re.IGNORECASE
            )
            if meta_refreshes:
                meta_url = meta_refreshes[0].strip("'\" ")
                next_url = urljoin(current_url, meta_url)
                meta_redirects.append(next_url)
                current_url = next_url
            else:
                break
        except Exception as e:
            log(f"[!] Meta-refresh parsing failed: {e}")
            break

    if meta_redirects:
        log("\nMeta-Redirect Chain Summary:")
        for idx, url in enumerate(meta_redirects, 1):
            log(f"{idx}. {url}")
    else:
        log("\nNo meta-refresh redirects followed.")

    # After all redirects - check final HTML for base64
    if final_html:
        decoded_targets_final_html = decode_base64_target(final_html)
        if decoded_targets_final_html:
            log("\nDecoded hidden base64 targets from final page HTML:")
            for decoded in decoded_targets_final_html:
                log(f"  {decoded}")

    parsed = urlparse(target_url)
    domain_for_ssl = parsed.netloc or parsed.path

    log("\nSSL Certificate Info:")
    ssl_info = get_ssl_info(domain_for_ssl)
    log(str(ssl_info))

    log("\nOpenSSL x509 Full Cert Dump:")
    try:
        openssl_dump = subprocess.check_output(
            f"echo | openssl s_client -connect {domain_for_ssl}:443 2>/dev/null | openssl x509 -noout -text",
            shell=True, timeout=15
        ).decode()
        for line in openssl_dump.strip().split("\n"):
            log(line.strip())
    except Exception as e:
        log(f"[!] OpenSSL cert dump failed: {e}")

    log("\nInput Fields:")
    for i in extract_inputs(final_html) or ["- None"]:
        log(f"- {i}")

    log("\nIframes Found:")
    for iframe in extract_iframes(final_html) or ["- None"]:
        log(f"- {iframe}")

    log("\nEmails Found:")
    for email in extract_emails(final_html) or ["- None"]:
        log(f"- {email}")

    log("\nExternal Scripts:")
    for script in extract_scripts(final_html, domain_for_ssl) or ["- None"]:
        log(f"- {script}")

    log("\nMeta Tags:")
    for meta in re.findall(r"<meta[^>]+>", final_html, re.IGNORECASE) or ["- None"]:
        log(f"- {meta}")

    log("\nForm Discovery (via curl grep):")
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

    log("\nRaw HTML Copy (curl -o):")
    try:
        raw_path = f"reports/raw_{domain_for_ssl}_{timestamp}.html"
        subprocess.run(["curl", "-s", target_url, "-o", raw_path], timeout=15)
        log(f"Saved raw HTML to {raw_path}")
    except Exception as e:
        log(f"[!] Raw HTML save failed: {e}")

    log("\nNmap Scan (Top 1000 ports):")
    try:
        ip = socket.gethostbyname(domain_for_ssl)
        log(f"[DEBUG] Resolved IP: {ip}")
        nmap_result = subprocess.check_output(
            ["nmap", "-sV", "--top-ports", "1000", ip],
            timeout=240
        ).decode()
        for line in nmap_result.strip().split("\n"):
            log(line)
    except Exception as e:
        log(f"[!] Nmap scan failed: {e}")

    log("\nShodan Recon:")
    if SHODAN_ENABLED:
        try:
            ip = socket.gethostbyname(domain_for_ssl)
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

    log("\nDIRB Scan (/usr/share/dirb/wordlists/common.txt):")
    try:
        dirb_result = subprocess.check_output(
            ["dirb", target_url, "/usr/share/dirb/wordlists/common.txt", "-r", "-S"],
            stderr=subprocess.DEVNULL,
            timeout=600
        ).decode()

        for line in dirb_result.strip().split("\n"):
            if "==>" in line or "CODE:" in line:
                log(line)
    except Exception as e:
        log(f"[!] DIRB scan failed: {e}")

    log("\nDeep Recon Complete.\n")
