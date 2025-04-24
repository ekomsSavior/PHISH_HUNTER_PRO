import subprocess
import os
import socket
import requests
import time

def run_scan(domain):
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")

    # Sanitize domain for safe filename
    safe_domain = domain.replace("http://", "").replace("https://", "").replace("/", "_")
    report_path = f"reports/{safe_domain}_scan_{timestamp}.txt"

    os.makedirs("reports", exist_ok=True)

    with open(report_path, "w") as report:
        report.write(f"=== PHISH HUNTER SCAN REPORT ===\nTarget: {domain}\nTimestamp: {timestamp}\n\n")

        # DNS Resolution
        try:
            ip = socket.gethostbyname(safe_domain.split("/")[0])
            report.write(f"[+] Resolved IP: {ip}\n")
            print(f"[+] IP: {ip}")
        except socket.gaierror:
            report.write(f"[-] Could not resolve domain: {domain}\n")
            print(f"[-] Could not resolve domain")
            return

        # WHOIS Lookup
        report.write("\n=== WHOIS ===\n")
        try:
            result = subprocess.check_output(["whois", safe_domain.split("/")[0]], stderr=subprocess.DEVNULL).decode()
            report.write(result + "\n")
        except:
            report.write("[-] WHOIS failed\n")

        # HTTP Headers
        report.write("\n=== HTTP Headers ===\n")
        try:
            headers = requests.get(f"http://{safe_domain}", timeout=10).headers
            for key, value in headers.items():
                report.write(f"{key}: {value}\n")
        except:
            report.write("[-] Could not retrieve HTTP headers\n")

        # Robots.txt
        report.write("\n=== robots.txt ===\n")
        try:
            response = requests.get(f"http://{safe_domain}/robots.txt", timeout=10)
            if response.status_code == 200:
                report.write(response.text + "\n")
            else:
                report.write("[-] robots.txt not found\n")
        except:
            report.write("[-] Error retrieving robots.txt\n")

        # Redirect Trace
        report.write("\n=== Redirect Trace ===\n")
        try:
            response = requests.get(f"http://{safe_domain}", timeout=10, allow_redirects=True)
            for r in response.history:
                report.write(f"{r.status_code} -> {r.url}\n")
            report.write(f"{response.status_code} -> {response.url}\n")
        except:
            report.write("[-] Redirect trace failed\n")

        # Passive Recon Links
        report.write("\n=== Passive Recon ===\n")
        report.write(f"- VirusTotal: https://www.virustotal.com/gui/domain/{safe_domain}\n")
        report.write(f"- URLScan: https://urlscan.io/domain/{safe_domain}\n")
        report.write(f"- crt.sh: https://crt.sh/?q=%25{safe_domain}\n")

    print(f"[✔] Scan saved to {report_path}")
