# PHISH_HUNTER_PRO

Advanced phishing investigation and disruption toolkit written in Python.

![IMG_4518](https://github.com/user-attachments/assets/7a5d70cd-b3cc-4bc3-94e7-f80d9fa8eeec)

PHISH_HUNTER_PRO is a modular Python-based anti-phishing reconnaissance and disruption toolkit.  

Created by me ekomsSavior, it is designed for security researchers, cyber defenders, and OSINT specialists to investigate and take action against phishing infrastructure.

It performs deep web page analysis, login page spam, open port scanning, SSL certificate inspection, metadata extraction, Shodan lookups, VirusTotal enrichment, and more.

---

## INSTALLATION

Clone the repository

```bash
git clone https://github.com/ekomsSavior/PHISH_HUNTER_PRO.git
cd PHISH_HUNTER_PRO
```

Install required tools and libraries

```bash
sudo apt update && sudo apt install tor dirb nmap curl python3-requests -y
sudo apt install python3-socks -y
```

---

## RUNNING THE TOOL

Start Tor before using the spammer

```bash
sudo systemctl start tor@default
```

Then launch the tool

```bash
python3 cli.py
```

You’ll see

```
[1] Scan Domain           – WHOIS, DNS headers, basic fingerprinting  
[2] Spam Login Page       – Sends fake logins through Tor + proxy  
[3] Deep Recon            – Full phishing investigation pipeline
```

---

## SCANNER MODULE 

  - Pull WHOIS and DNS records

  - Use whatweb to detect technologies used on the page

  - Help you identify red flags like shady registrars or reused infrastructure

  - Provide clickable links to report the site to:

---


## SPAMMER MODULE

Use the spammer to disrupt phishing login forms with fake randomized logins.

Features
- Tor SOCKS5 support  
- Circuit rotation using `pkill -HUP tor` (no config needed)  
- User-agent randomization  
- Optional proxy rotation

## USING A PROXY LIST

To rotate proxies if Tor fails

1. Create a file called `proxy_list.txt` in the project directory.
2. Add one proxy per line, like this

```
http://123.45.67.89:8080
socks5://98.76.54.32:1080
```

The tool will automatically use these if Tor is blocked or unavailable.

---

##  WHAT DEEP RECON MODULE DOES

- Follows and logs HTTP redirects (curl -L -I)

-  Live-tracks meta-refresh redirects inside HTML (chases hidden redirect chains)

-   Decodes Base64-encoded URLs hidden in redirects or inside page source (e.g., target=BASE64...)

-   Analyzes SSL certificates via OpenSSL (openssl s_client)

-   Extracts metadata: input fields, iframes, external scripts, emails, meta tags

-   Saves a raw HTML snapshot of each visited page to the reports/ folder

-   Performs form discovery with curl and grep

-   Runs an Nmap scan with version detection (nmap -sV --top-ports 1000)

 -   Queries Shodan for IP intelligence (optional, if API key installed)

 -  (Coming soon) Checks VirusTotal for malicious reports (placeholder ready)

  - Runs a DIRB directory brute-force scan (dirb), now more responsive
---

## API KEY SETUP

The Deep Recon module supports Shodan and VirusTotal lookups.

Edit the top of `deep_recon.py` to insert your keys

```python
SHODAN_API_KEY = "your_key_here"
VT_API_KEY = "your_key_here"
```


---


## ADDITIONAL TIPS

- The Deep Recon module saves raw HTML pages — inspect them in your browser to discover hidden fields, script injections, and backdoors.
- DIRB scan results depend on the structure of the target. Static pages or dead buckets may return no results. 
- Use tools like `ffuf`, `dirb`, or `gobuster` with custom wordlists for advanced enumeration.  
- Use `curl -v` to explore redirect chains or form behavior.  
- Query phishing site IPs directly on [https://shodan.io](https://shodan.io) for infrastructure recon.
- Check out **Phish Breaker** — an all-in-one toolkit to smash scams, sweep Google buckets, and run deep forensic scans.  
Repo: [https://github.com/ekomsSavior/phish_breaker](https://github.com/ekomsSavior/phish_breaker)

---

## STAY TUNED

This is an evolving project. Future updates will include:

- Real-time dashboards  
- Advanced evasions  
- Better visualizations  
- More automation modules  

Watch this repo or follow me on IG for updates.

GitHub: https://github.com/ekomsSavior  

Instagram: https://instagram.com/ekoms.is.my.savior  

---

## DISCLAIMER

**PHISH_HUNTER_PRO is for ethical use only.**  

You must have permission to test on networks.

Use responsibly. You accept full liability for how you use this software.

---

## AUTHOR

Crafted with soul and purpose by

**ek0ms savi0r**  

https://github.com/ekomsSavior

https://instagram.com/ekoms.is.my.savior

Check out my Medium article about Phish Hunter Pro-

https://medium.com/@ekoms1/phish-hunter-pro-b3cc30041f91

