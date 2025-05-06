from scanner import run_scan
from spammer import run_spam
from deep_recon import run_deep_recon
from fuzzer import fuzz_menu
from mini_scanner import run_mini_scanner
import subprocess
import csv
import time
import os

def banner():
    print("""
██████╗ ██╗  ██╗██╗███████╗██╗  ██╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██╔══██╗██║  ██║██║██╔════╝██║  ██║    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██████╔╝███████║██║███████╗███████║    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██╔═══╝ ██╔══██║██║╚════██║██╔══██║    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
██║     ██║  ██║██║███████║██║  ██║    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
                                 by ekoms savior
""")

def renew_tor_circuit():
    try:
        subprocess.run(["sudo", "pkill", "-HUP", "tor"], check=True)
        print("[✔] Tor circuit refreshed with sudo pkill -HUP tor")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to rotate Tor circuit: {e}")

def try_smart_spam(url, duration):
    end_time = time.time() + duration
    while time.time() < end_time:
        run_spam(url, proxy_file=None, delay_enabled=False, use_tor=False, duration=duration)

def run_bulk_scan():
    CSV_FILE = input("Enter path to domain CSV file (e.g., domains.csv): ").strip()
    REPORTS_DIR = "reports"
    LOG_FILE = os.path.join(REPORTS_DIR, "bulk_log.txt")
    PYTHON_PATH = "python3"

    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR)

    domains = set()
    try:
        with open(CSV_FILE, newline='') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                if row and row[0]:
                    domain = row[0].strip().lower()
                    if not domain.startswith("http"):
                        domain = f"https://{domain}"
                    domains.add(domain)
    except FileNotFoundError:
        print(f"[!] File not found: {CSV_FILE}")
        return

    domains = list(domains)
    print(f"[+] Loaded {len(domains)} domains.")

    module_map = {
        "1": "scanner.py",
        "2": "spammer.py",
        "3": "deep_recon.py"
    }
    module_choice = input("Select module (1 = scanner, 2 = spammer, 3 = deep_recon): ")
    module = module_map.get(module_choice)

    if not module:
        print("[!] Invalid module choice. Exiting bulk scan.")
        return

    if module_choice == "2":
        duration = int(input("Enter duration (seconds) to spam each domain: "))
        while True:
            for domain in domains:
                print(f"[+] Spamming {domain} for {duration} seconds...")
                try_smart_spam(domain, duration)
    else:
        for domain in domains:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            print(f"[+] Running {module} on: {domain}")
            command = [PYTHON_PATH, module, domain]

            try:
                result = subprocess.run(command, capture_output=True, text=True, check=True)
                safe_domain = domain.replace("https://", "").replace("http://", "").replace("/", "_")
                report_path = os.path.join(REPORTS_DIR, f"{safe_domain}_output.txt")
                output = result.stdout.strip()
                if not output:
                    output = "[!] No output captured. Possible error in script."
                with open(report_path, "w") as out_file:
                    out_file.write(output)
                log_entry = f"{timestamp} | {domain} | SUCCESS\n"
            except subprocess.CalledProcessError as e:
                log_entry = f"{timestamp} | {domain} | FAILED | {e}\n"

            with open(LOG_FILE, "a") as log:
                log.write(log_entry)

            time.sleep(1)  # avoid hammering servers

def display_menu():
    print("\n[1] Scan Domain (single)")
    print("[2] Spam Login Page (single)")
    print("[3] Deep Recon (single)")
    print("[4] Fuzzing + Attack Surface Discovery")
    print("[5] Bulk Scan, Spam or Deep Recon")
    print("[6] Mini Scanner (Param Injection + Reflections)")
    print("[0] Exit\n")

def main():
    banner()
    while True:
        display_menu()
        choice = input("\nEnter your choice: ")

        if choice == '1':
            domain = input("Enter domain to scan: ")
            run_scan(domain)
        elif choice == '2':
            url = input("Enter phishing URL: ")
            run_spam(url, proxy_file=None, delay_enabled=False, use_tor=False, duration=30)
        elif choice == "3":
            target = input("Enter domain or URL: ").strip()
            run_deep_recon(target)
        elif choice == "4":
            fuzz_menu()
        elif choice == "5":
            run_bulk_scan()
        elif choice == '6':
            run_mini_scanner()
        elif choice == '0':
            print("Goodbye.")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
