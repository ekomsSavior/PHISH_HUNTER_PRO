def load_user_agents():
    try:
        with open("user_agents.txt", "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("[!] user_agents.txt not found. Using default User-Agent.")
        return ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)"]

def load_proxies(proxy_file):
    try:
        with open(proxy_file, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("[!] Proxy file not found.")
        return []
