import subprocess
import os
import socket
import requests
import time
import sys
from urllib.parse import urlparse

def run_scan(domain):
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    parsed = urlparse(domain)
    hostname = parsed.hostname or domain.replace("http://", "").replace("https://", "").strip("/")
    safe_domain = hostname.replace("/", "_")
    report_content = f"=== PHISH HUNTER PRO SCAN REPORT ===\nTarget: {domain}\nTimestamp: {timestamp}\n\n"

    # DNS Resolution
    try:
        ip = socket.gethostbyname(hostname)
        report_content += f"[+] Resolved IP: {ip}\n"
    except socket.gaierror:
        report_content += f"[-] Could not resolve domain: {hostname}\n"

    # WHOIS Lookup
    report_content += "\n=== WHOIS ===\n"
    try:
        result = subprocess.check_output(["whois", hostname], stderr=subprocess.DEVNULL).decode()
        report_content += result + "\n"
        whois_success = True
    except Exception:
        report_content += "[-] WHOIS failed\n"
        result = ""
        whois_success = False

    # Abuse Contacts
    report_content += "\n=== Abuse Contacts ===\n"
    try:
        abuse_lines = []
        whois_lines = result.splitlines()
        for line in whois_lines:
            if any(word in line.lower() for word in ['abuse', 'contact', 'email']):
                abuse_lines.append(line.strip())
        if abuse_lines:
            for abuse in sorted(set(abuse_lines)):
                report_content += abuse + "\n"
        else:
            report_content += "[-] No abuse contacts found in WHOIS.\n"
    except Exception:
        report_content += "[-] Failed to parse abuse contacts.\n"

    # HTTP Headers (with fallback to HTTPS)
    report_content += "\n=== HTTP Headers ===\n"
    headers = None
    try:
        headers = requests.get(f"http://{hostname}", timeout=10).headers
    except Exception:
        try:
            headers = requests.get(f"https://{hostname}", timeout=10).headers
        except Exception:
            headers = None

    if headers:
        for key, value in headers.items():
            report_content += f"{key}: {value}\n"
    else:
        report_content += "[-] Could not retrieve HTTP headers\n"

    # robots.txt (with fallback to HTTPS)
    report_content += "\n=== robots.txt ===\n"
    try:
        response = requests.get(f"http://{hostname}/robots.txt", timeout=10)
        if response.status_code == 200:
            report_content += response.text + "\n"
        else:
            raise Exception()
    except Exception:
        try:
            response = requests.get(f"https://{hostname}/robots.txt", timeout=10)
            if response.status_code == 200:
                report_content += response.text + "\n"
            else:
                report_content += "[-] robots.txt not found\n"
        except Exception:
            report_content += "[-] Error retrieving robots.txt\n"

    # Redirect Trace (with fallback to HTTPS)
    report_content += "\n=== Redirect Trace ===\n"
    try:
        response = requests.get(f"http://{hostname}", timeout=10, allow_redirects=True)
        for r in response.history:
            report_content += f"{r.status_code} -> {r.url}\n"
        report_content += f"{response.status_code} -> {response.url}\n"
    except Exception:
        try:
            response = requests.get(f"https://{hostname}", timeout=10, allow_redirects=True)
            for r in response.history:
                report_content += f"{r.status_code} -> {r.url}\n"
            report_content += f"{response.status_code} -> {response.url}\n"
        except Exception:
            report_content += "[-] Redirect trace failed\n"

    # Passive Recon Links
    report_content += "\n=== Passive Recon Links ===\n"
    report_content += f"- VirusTotal: https://www.virustotal.com/gui/domain/{hostname}\n"
    report_content += f"- URLScan: https://urlscan.io/domain/{hostname}\n"
    report_content += f"- crt.sh (SSL certificates): https://crt.sh/?q={hostname}\n"
    report_content += f"- AbuseIPDB: https://www.abuseipdb.com/check/{hostname}\n"

    # Official Reporting Links
    report_content += "\n=== Report This Phishing Site ===\n"
    report_content += "- Google Safe Browsing: https://safebrowsing.google.com/safebrowsing/report_phish/\n"
    report_content += "- APWG Report Phishing: https://apwg.org/reportphishing/\n"
    report_content += "- Microsoft Report Phishing: https://www.microsoft.com/en-us/wphish/\n"

    # Final Recommendations
    report_content += "\n=== Recommended Next Steps ===\n"
    report_content += "1. Report this URL to Google Safe Browsing.\n"
    report_content += "2. Report to APWG and Microsoft.\n"
    report_content += "3. Email any abuse contacts found above.\n"
    report_content += "4. Optionally submit the URL to antivirus vendors.\n"
    report_content += "5. Continue deeper recon with tools like urlscan.io and crt.sh.\n"

    # Print to stdout so bulk runner can save it
    print(report_content)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        domain = sys.argv[1]
        run_scan(domain)
    else:
        print("[!] No domain provided.")

