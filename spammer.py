#!/usr/bin/env python3

import requests
import random
import time
import sys
from utils import load_user_agents, load_proxies
from faker import Faker

fake = Faker()

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

def run_flexible_contact_spam(url, duration, proxy_file=None, delay_enabled=False, use_tor=False):
    user_agents = load_user_agents()
    proxies = load_proxies(proxy_file) if proxy_file else []
    tor_proxy = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}
    session = requests.Session()

    print("\n[+] Toggle which fields to include in the form submission:")

    include = lambda label: input(f"Include {label}? (y/n): ").strip().lower() == 'y'

    use_first = include("First Name")
    use_last = include("Last Name")
    use_email = include("Email")
    use_phone = include("Phone Number")
    use_address = include("Address")
    use_subject = include("Subject")
    use_message = include("Message")

    custom_fields = []
    if include("any custom fields"):
        while True:
            name = input("→ Field name: ").strip()
            value_type = input("   Use random or static value? (random/static): ").strip().lower()
            if value_type == "random":
                custom_fields.append((name, "random"))
            else:
                static_val = input("   Enter static value: ")
                custom_fields.append((name, static_val))
            if input("Add another custom field? (y/n): ").lower() != 'y':
                break

    select_fields = []
    if include("any dropdown/select fields"):
        while True:
            name = input("→ Field name: ").strip()
            options = input("   Enter options (comma separated): ").split(",")
            options = [o.strip() for o in options if o.strip()]
            select_fields.append((name, options))
            if input("Add another dropdown field? (y/n): ").lower() != 'y':
                break

    print("\n[+] Starting flexible contact spammer...")

    end_time = time.time() + duration
    while time.time() < end_time:
        headers = {"User-Agent": random.choice(user_agents)}
        proxy = random.choice(proxies) if proxies else None
        proxy_dict = {"http": proxy, "https": proxy} if proxy else (tor_proxy if use_tor else {})

        data = {}

        if use_first:   data["first_name"] = fake.first_name()
        if use_last:    data["last_name"] = fake.last_name()
        if use_email:   data["email"] = fake.email()
        if use_phone:   data["phone"] = fake.phone_number()
        if use_address: data["address"] = fake.address()
        if use_subject: data["subject"] = "Contact Me"
        if use_message: data["message"] = random.choice([
            "You’ve been reported to Google Safe Browsing.",
            "This domain is now under investigation.",
            "This phishing site is flagged and logged.",
            "Law enforcement will be notified. Take it down."
        ])

        for field, val in custom_fields:
            data[field] = fake.word() if val == "random" else val

        for field, options in select_fields:
            data[field] = random.choice(options)

        try:
            r = session.post(url, data=data, headers=headers, proxies=proxy_dict, timeout=10)
            print(f"[+] Sent | HTTP {r.status_code} | Data: {data}")
        except Exception as e:
            print(f"[!] Error: {e}")

        if delay_enabled:
            time.sleep(random.randint(1, 3))

if __name__ == "__main__":
    if len(sys.argv) > 2:
        duration_per_domain = int(input("Enter duration (seconds) to spam each domain: "))
        domains = sys.argv[1:]
        run_bulk_spam(domains, duration_per_domain)
    else:
        print("[!] Usage: python3 spammer.py <domain1> <domain2> ...")
