#!/usr/bin/env python3
import requests
import os
import time
import random
import uuid

REPORTS_DIR = "reports"
USE_TOR = True  # Set to True to enable Tor proxy

# Expanded header rotation list
HEADERS_LIST = [
    {"User-Agent": "Mozilla/5.0"},
    {"User-Agent": "Googlebot"},
    {"User-Agent": "sqlmap"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Requested-With": "XMLHttpRequest"},
    {"Referer": "https://google.com"},
    {"Cache-Control": "no-cache"},
    {"X-Request-ID": str(uuid.uuid4())},
    {"DNT": "1"},
    {"Upgrade-Insecure-Requests": "1"}
]

def get_random_headers():
    base = random.choice(HEADERS_LIST)
    base["X-Request-ID"] = str(uuid.uuid4())
    return base

def get_proxies():
    if USE_TOR:
        return {
            "http": "socks5h://127.0.0.1:9050",
            "https": "socks5h://127.0.0.1:9050"
        }
    return {}

def save_report_line(report_path, line):
    os.makedirs(REPORTS_DIR, exist_ok=True)
    with open(report_path, "a") as f:
        f.write(line + "\n")

def load_wordlist(path):
    try:
        with open(path) as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] Wordlist file not found: {path}")
        return []

def send_request(url, headers=None):
    delay()
    try:
        headers = headers or get_random_headers()
        r = requests.get(url, headers=headers, proxies=get_proxies(), timeout=10)
        code = r.status_code

        if code == 429:
            wait = int(r.headers.get("Retry-After", random.randint(5, 15)))
            print(f"[!] 429 Too Many Requests — Sleeping {wait}s")
            time.sleep(wait + 1)

        if code not in [404, 400]:
            print(f"[!] {url} → {code}")
        return r

    except Exception as e:
        print(f"[!] Request error at {url}: {e}")
        return None

def delay():
    if SPEED_MODE == "1":  # Fast
        return
    elif SPEED_MODE == "2":  # Normal
        time.sleep(random.uniform(1.5, 3.5))
    elif SPEED_MODE == "3":  # Stealth
        time.sleep(random.uniform(5.0, 7.5))

def fuzz_path(target, wordlist, report_path):
    print(f"[+] Starting path fuzz on {target}")
    seen = set()
    for i, word in enumerate(wordlist):
        url = f"{target.rstrip('/')}/{word}"
        if url in seen:
            continue
        seen.add(url)

        r = send_request(url)
        if r and r.status_code not in [404, 400]:
            msg = f"[!] {url} → {r.status_code}"
            print(msg)
            save_report_line(report_path, msg)
        if i % 10 == 0:
            time.sleep(3)

def fuzz_headers(target, report_path):
    print(f"[+] Starting header fuzz on {target}")
    seen = set()
    for i, header in enumerate(HEADERS_LIST):
        url = f"{target}"
        if str(header) in seen:
            continue
        seen.add(str(header))

        r = send_request(url, headers=header)
        if r and r.status_code >= 400:
            msg = f"[!] {target} with {header} → {r.status_code}"
            print(msg)
            save_report_line(report_path, msg)
        if i % 10 == 0:
            time.sleep(3)

def fuzz_params(target, wordlist, report_path):
    print(f"[+] Starting param fuzz on {target}")
    seen = set()
    for i, word in enumerate(wordlist):
        url = f"{target}?id={word}"
        if url in seen:
            continue
        seen.add(url)

        r = send_request(url)
        if r and r.status_code not in [404, 400]:
            msg = f"[!] {url} → {r.status_code}"
            print(msg)
            save_report_line(report_path, msg)
        if i % 10 == 0:
            time.sleep(3)

def fuzz_subdomains(file_path_or_domain, wordlist, report_path):
    seen = set()

    if os.path.isfile(file_path_or_domain):
        try:
            with open(file_path_or_domain) as f:
                subdomains = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] Subdomain file not found: {file_path_or_domain}")
            return
    else:
        subdomains = [file_path_or_domain]

    for sub in subdomains:
        if not sub.startswith("http://") and not sub.startswith("https://"):
            sub = "http://" + sub

        for i, word in enumerate(wordlist):
            url = f"{sub.rstrip('/')}/{word}"
            if url in seen:
                continue
            seen.add(url)

            r = send_request(url)
            if r and r.status_code not in [404, 400]:
                msg = f"[!] {url} → {r.status_code}"
                print(msg)
                save_report_line(report_path, msg)

            if i % 10 == 0:
                time.sleep(3)

def fuzz_menu():
    global SPEED_MODE
    target = input("Enter single domain or path to subdomains file: ").strip()
    wordlist_path = input("Enter fuzzing wordlist path (default: wordlist.txt): ").strip()
    if not wordlist_path:
        wordlist_path = "wordlist.txt"

    wordlist = load_wordlist(wordlist_path)
    if not wordlist:
        return

    print("""
Select Fuzzing Speed:
[1] Fast (No delay)
[2] Normal (2–4s delay)
[3] Stealth (5–7s + full header + TOR)
""")
    SPEED_MODE = input("Choose fuzz mode [1/2/3]: ").strip()

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    if os.path.isfile(target):
        base_name = os.path.basename(target).split("_")[0]
        report_file = os.path.join(REPORTS_DIR, f"{base_name}_subdomains_fuzz_{timestamp}.txt")
    else:
        clean_name = target.replace("http://", "").replace("https://", "").replace("/", "_")
        report_file = os.path.join(REPORTS_DIR, f"{clean_name}_fuzz_{timestamp}.txt")

    print(f"\n[✔] Report will be saved to {report_file}\n")

    print("""
=== Fuzzing Modes ===
[1] Path Fuzz (/FUZZ)
[2] Header Fuzz
[3] Param Fuzz (?id=FUZZ)
[4] Subdomain Path Fuzz (subdomain/FUZZ)
[5] Full Combo (All Modes)
""")
    choice = input("Select an option: ").strip()

    start_time = time.strftime("%Y-%m-%d %H:%M:%S")
    save_report_line(report_file, f"\n=== Fuzz Report {start_time} ===")

    if choice == '1':
        fuzz_path(target, wordlist, report_file)
    elif choice == '2':
        fuzz_headers(target, report_file)
    elif choice == '3':
        fuzz_params(target, wordlist, report_file)
    elif choice == '4':
        fuzz_subdomains(target, wordlist, report_file)
    elif choice == '5':
        fuzz_path(target, wordlist, report_file)
        fuzz_headers(target, report_file)
        fuzz_params(target, wordlist, report_file)
        fuzz_subdomains(target, wordlist, report_file)
    else:
        print("[!] Invalid choice")

    save_report_line(report_file, "=== End of Fuzz Report ===\n")
    print(f"\n[✔] Report saved to {report_file}\n")

if __name__ == "__main__":
    fuzz_menu()
