from scanner import run_scan
from spammer import run_spam
from deep_recon import run_deep_recon
import stem
import stem.control

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
        with stem.control.Controller.from_port(port=9051) as controller:
            controller.authenticate()  # Or use password="yourpassword" if needed
            controller.signal(stem.Signal.NEWNYM)
            print("[✔] Requested new Tor circuit.")
    except Exception as e:
        print(f"[!] Failed to renew Tor circuit: {e}")

def try_smart_spam(url):
    try:
        renew_tor_circuit()
        print("[*] Trying spam with Tor first...")
        run_spam(url, proxy_file=None, delay_enabled=False, use_tor=True)
    except Exception as e:
        print(f"[!] Tor failed: {e}")
        try:
            print("[*] Trying with proxies from proxy_list.txt...")
            run_spam(url, proxy_file="proxy_list.txt", delay_enabled=False, use_tor=False)
        except Exception as e:
            print(f"[!] Proxies failed too: {e}")
            print("[*] Sending spam directly (no proxy or Tor)...")
            run_spam(url, proxy_file=None, delay_enabled=False, use_tor=False)

def display_menu():
    print("\n[1] Scan Domain           – Run WHOIS, DNS, headers, and basic fingerprinting")
    print("[2] Spam Login Page       – Send fake logins to phishing forms (with Tor + proxy fallback)")
    print("[3] Deep Recon            – Hunt scam trails, follow redirects, check certs, more")
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
            try_smart_spam(url)
        elif choice == "3":
            target = input("Enter domain or URL: ").strip()
            run_deep_recon(target)
        elif choice == '0':
            print("Goodbye.")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
