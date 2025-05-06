import requests
import os
import time

HEADERS_LIST = [
    {"User-Agent": "Mozilla/5.0"},
    {"User-Agent": "Googlebot"},
    {"User-Agent": "sqlmap"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Requested-With": "XMLHttpRequest"},
    {"Referer": "https://google.com"},
]

REPORTS_DIR = "reports"

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

def fuzz_path(target, wordlist, report_path):
    print(f"[+] Starting path fuzz on {target}")
    for word in wordlist:
        url = f"{target.rstrip('/')}/{word}"
        try:
            r = requests.get(url, timeout=10)
            if r.status_code not in [404, 400]:
                msg = f"[!] {url} → {r.status_code}"
                print(msg)
                save_report_line(report_path, msg)
        except Exception as e:
            msg = f"[!] Request error at {url}: {e}"
            print(msg)
            save_report_line(report_path, msg)

def fuzz_headers(target, report_path):
    print(f"[+] Starting header fuzz on {target}")
    for header in HEADERS_LIST:
        try:
            r = requests.get(target, headers=header, timeout=10)
            if r.status_code >= 400:
                msg = f"[!] {target} with {header} → {r.status_code}"
                print(msg)
                save_report_line(report_path, msg)
        except Exception as e:
            msg = f"[!] Request error: {e}"
            print(msg)
            save_report_line(report_path, msg)

def fuzz_params(target, wordlist, report_path):
    print(f"[+] Starting param fuzz on {target}")
    for word in wordlist:
        url = f"{target}?id={word}"
        try:
            r = requests.get(url, timeout=10)
            if r.status_code not in [404, 400]:
                msg = f"[!] {url} → {r.status_code}"
                print(msg)
                save_report_line(report_path, msg)
        except Exception as e:
            msg = f"[!] Request error at {url}: {e}"
            print(msg)
            save_report_line(report_path, msg)

def fuzz_subdomains(file_path, wordlist, report_path):
    try:
        with open(file_path) as f:
            subdomains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] Subdomain file not found: {file_path}")
        return

    for sub in subdomains:
        for word in wordlist:
            url = f"http://{sub}/{word}"
            try:
                r = requests.get(url, timeout=10)
                if r.status_code not in [404, 400]:
                    msg = f"[!] {url} → {r.status_code}"
                    print(msg)
                    save_report_line(report_path, msg)
            except Exception as e:
                msg = f"[!] Request error at {url}: {e}"
                print(msg)
                save_report_line(report_path, msg)

def fuzz_menu():
    target = input("Enter single domain or path to subdomains file: ").strip()
    wordlist_path = input("Enter fuzzing wordlist path (default: wordlist.txt): ").strip()
    if not wordlist_path:
        wordlist_path = "wordlist.txt"

    wordlist = load_wordlist(wordlist_path)
    if not wordlist:
        return

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
