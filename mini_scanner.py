import requests
import time
import os
import sys

default_payloads = [
    "<script>alert(1)</script>", "1'", "1--", "1 OR 1=1",
    "admin", "debug", "dev"
]

common_params = ["id", "q", "search", "page", "query", "redirect", "url", "file"]

headers_list = [
    {"User-Agent": "Mozilla/5.0"},
    {"User-Agent": "Googlebot"},
    {"User-Agent": "sqlmap"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"Referer": "https://google.com"},
]

backend_error_signatures = ["sql", "syntax", "error", "exception", "mysql", "postgres", "ora-", "warning", "invalid query"]

def load_payloads():
    if len(sys.argv) > 1 and sys.argv[1].startswith("--payloads"):
        _, file_path = sys.argv[1].split("=")
        if os.path.exists(file_path):
            with open(file_path, "r") as f:
                return [line.strip() for line in f if line.strip()]
        else:
            print(f"[!] Payloads file not found: {file_path}, using default payloads.")
    return default_payloads

def mini_scan(target):
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    domain = target.split("//")[-1].replace("/", "_")
    report_file = f"reports/{domain}_miniscan_{timestamp}.txt"

    if not os.path.exists("reports"):
        os.makedirs("reports")

    baseline_url = f"{target}?id=test"
    try:
        baseline = requests.get(baseline_url, timeout=10).text
        with open(report_file, "w") as f:
            f.write(f"=== Baseline from {baseline_url} ===\n")
    except Exception as e:
        print(f"[!] Error getting baseline: {e}")
        return

    print(f"\n[+] Baseline collected from {baseline_url}\n")

    payloads = load_payloads()

    for param in common_params:
        for payload in payloads:
            url = f"{target}?{param}={payload}"
            for header in headers_list:
                try:
                    r = requests.get(url, headers=header, timeout=10)
                    status = r.status_code
                    body = r.text

                    reflected = payload in body or "<script>" in body or "onerror=" in body
                    backend_error = any(x in body.lower() for x in backend_error_signatures)
                    changed = body != baseline

                    msg = f"[!] {url} with {header} → {status}"
                    print(msg)

                    if status in [403, 500, 301, 302]:
                        print(f"    ⚠️ Interesting status code: {status}")
                        msg += f" | Interesting status {status}"
                    if reflected:
                        print("    ⚠️ Reflected param / possible DOM XSS")
                        msg += " | Reflected"
                    if backend_error:
                        print("    ⚠️ Backend error (possible SQLi)")
                        msg += " | Backend Error"
                    if changed:
                        print("    ⚠️ Behavior change")
                        msg += " | Behavior Changed"
                    if not any([reflected, backend_error, changed, status in [403,500,301,302]]):
                        print("    ✔️ Nothing interesting detected")
                        msg += " | No Issue"

                    with open(report_file, "a") as f:
                        f.write(msg + "\n")

                except Exception as e:
                    print(f"[!] Request error at {url}: {e}")
                    with open(report_file, "a") as f:
                        f.write(f"[!] {url} with {header} → ERROR: {e}\n")

    print(f"\n[✔] Mini scan complete. Report saved to {report_file}")

def run_mini_scanner():
    target = input("Enter domain (e.g., https://example.com): ").strip()
    if not target.startswith("http"):
        target = "https://" + target
    mini_scan(target)

if __name__ == "__main__":
    run_mini_scanner()

