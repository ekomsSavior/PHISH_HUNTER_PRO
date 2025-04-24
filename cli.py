from scanner import run_scan
from spammer import run_spam
from deep_recon import run_deep_recon

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

def display_menu():
    print("\n[1] Scan Domain           – Run WHOIS, DNS, headers, and basic fingerprinting")
    print("[2] Spam Login Page       – Send fake logins to phishing forms (with Tor + proxy)")
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
            run_spam(url)
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
