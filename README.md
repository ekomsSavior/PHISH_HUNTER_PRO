

# PHISH\_HUNTER\_PRO

Advanced phishing investigation and disruption toolkit written in Python.

![IMG\_4518](https://github.com/user-attachments/assets/7a5d70cd-b3cc-4bc3-94e7-f80d9fa8eeec)


**PHISH\_HUNTER\_PRO** is a modular Python toolkit for investigating and disrupting phishing websites.

It includes tools for scanning, form flooding, XSS and SQLi fuzzing, denial-of-service (DoS) disruption, open port scanning, SSL certificate inspection, and metadata analysis. 
The framework supports Tor routing, proxy rotation, and integrates with services like Shodan and VirusTotal.

Built for security researchers, OSINT analysts, and defenders tracking malicious infrastructure.


---

## INSTALLATION

Clone the repository

```bash
git clone https://github.com/ekomsSavior/PHISH_HUNTER_PRO.git
cd PHISH_HUNTER_PRO
```

Install required tools and libraries

```bash
sudo apt update && sudo apt install tor parallel dirb nmap sublist3r curl python3-requests python3-scapy -y
sudo apt install python3-socks -y
```

Install Faker

```bash
pip3 install Faker --break-system-packages                #faker is for the contact form spammer, if your not interested in that module you can skip faker install
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
[1] Scan Domain (single)
[2] Spam Login Page (single)
[3] Deep Recon (single)
[4] Fuzzing + Attack Surface Discovery
[5] Bulk Scan, Spam or Deep Recon
[6] Mini Scanner (Param Injection + Reflections)
[7] Flexible Contact Spammer (toggle fields)
[8] DoS Attack Module (multi-protocol)
[9] Hardcore DoS Mode (fast + raw)
[10] Mass Param Bombing / SQLi Fuzz Loop 
[11] Full Disruption Script (Spam + DoS + Fuzz) 
[12] XSS Payload Injector (Reflected & Dom)
[0] Exit
```

---

## SCANNER MODULE

* Pulls WHOIS and DNS records
* Uses WhatWeb to fingerprint technologies
* Identifies red flags like shady registrars or reused infrastructure
* Provides direct reporting links

---

## SPAMMER MODULE

Disrupt phishing login forms by flooding them with randomized fake logins.

**Features**

* Tor SOCKS5 support
* Circuit rotation using `pkill -HUP tor` (no extra config)
* User-agent randomization
* Optional proxy rotation

---

## USING A PROXY LIST

If Tor is blocked, rotate proxies:

1. Create a file called `proxy_list.txt` in the project directory.
2. Add one proxy per line, like:

```
http://123.45.67.89:8080  
socks5://98.76.54.32:1080
```

The tool will automatically use these if Tor is unavailable.

---

## CONTACT FORM SPAMMER MODULE

Flood phishing contact forms with realistic spam using dynamic field toggles and Faker-generated data.

Features

* Select which fields to include (first name, last name, email, phone, address, etc)
* Add custom field names and value
* Handle dropdown/select boxes (e.g., “Best time to contact you”)
* Randomized insults or abuse report messages
* User-agent rotation
* Tor and proxy support
* Logs each attempt with full payload

---

## DEEP RECON MODULE

* Follows and logs HTTP redirects (`curl -L -I`)
* Tracks meta-refresh redirects inside HTML (chasing hidden redirect chains)
* Decodes Base64-encoded URLs in redirects or page source (`target=BASE64...`)
* Analyzes SSL certificates (`openssl s_client`)
* Extracts metadata: input fields, iframes, external scripts, emails, meta tags
* Saves raw HTML snapshots to the `reports/` folder
* Performs form discovery (`curl | grep`)
* Runs Nmap with version detection (`nmap -sV --top-ports 1000`)
* Queries Shodan for IP intelligence (optional, if API key provided)
* Queries VirusTotal for domain and IP reputation
* Runs DIRB directory brute-force (`dirb`), tuned for responsiveness
* Runs Sublist3r for subdomain enumeration

---

## FUZZING MODULE

* Path fuzzing → [https://target/FUZZ](https://target/FUZZ)
* Header fuzzing → rotates headers, logs server errors
* Parameter fuzzing → [https://target/page?id=FUZZ](https://target/page?id=FUZZ)
* Subdomain path fuzzing → fuzzes across enumerated subdomains

---

## MINI SCANNER MODULE

Injects payloads like `<script>alert(1)</script>`, `'1--`, `1 OR 1=1`
Scans common params: `id`, `q`, `search`, `page`, `query`, `redirect`, `url`, `file`
Rotates headers to test backend behavior

**Flags:**

* Reflected input (possible XSS)
* Backend errors (possible SQLi, command injection)
* Behavior changes
* Interesting status codes (403, 500, 301/302)

📁 Saves individual reports for every scan
📁 Saves injection targets to `loot/param_targets.txt` for use in Module 12

---

## BULK SCAN MODE

Run any module across a list of domains:

1. Prepare a CSV file (e.g., `domains.csv`)

```
phishingsite1.com  
phishingsite2.net  
phishingsite3.org
```

2. Select **Option 4** in the menu and point it to your file.
   Reports and logs will be saved in the `reports/` folder automatically.

---

## API KEY SETUP

The Deep Recon module supports Shodan and VirusTotal.

Edit the top of `deep_recon.py` to insert your keys:

```python
SHODAN_API_KEY = "your_key_here"
VT_API_KEY = "your_key_here"
```

---

## DoS MODULE (STANDARD)

Launch multi-threaded denial-of-service attacks against phishing sites.

**Features**

* Configurable thread count (e.g. 50, 100, 250)
* Supports both HTTP and HTTPS targets
* Sends randomized header floods using valid syntax
* Targets `GET` endpoints only for stealth and compatibility
* Basic request delay randomization to avoid instant detection

**Usage**
Select option `[8] DoS Attack Module (multi-protocol)` in the CLI and provide:

* The phishing URL (http or https)
* Number of threads to use

Note: Use responsibly. Some phishing sites are behind WAF/CDNs and may not respond immediately.

---

## HARDCORE DoS MODE

An advanced, stealth-capable version of the DoS engine.

**Features**

* Tor routing for obfuscation
* Raw socket option (HTTP only)
* Header randomization + bot-like behavior
* Supports higher thread volume (e.g. 200–1000)
* Includes failsafe to bypass if Tor is unreachable

**Usage**
Choose `[9] Hardcore DoS Mode (fast + raw)` and enter:

* Target URL
* Thread count
* Whether to use Tor (y/n)

Use this with discretion, especially during red team demos or controlled takedowns.

---

## NEW: MASS PARAM BOMBING / SQLi Fuzz Loop

Launches mass injections across common parameters like `id`, `q`, `query`, `page`, `url`, and more.

**Features**

* Rotates payloads such as `'1 OR 1=1`, `<script>`, `--`, etc.
* Rotates User-Agent and Referer headers
* Flags backend error signatures (SQL, syntax, stack trace)
* Logs duplicate 200 responses to detect fake pages or honeypots
* Optionally runs with **Tor stealth routing**

Useful for:

* SQL injection fuzzing
* Testing WAF behavior
* Identifying parameter reflection vectors

---

## NEW: FULL DISRUPTION SCRIPT

 Combines **Spammer**, **DoS**, and **Fuzzer** into a single attack chain.

**Features**

* Launches randomized fake login floods (from Module 2)
* Sends multi-threaded DoS (from Module 8)
* Runs fuzzer across common endpoints

Great for red team demos or takedown simulations.

---

## NEW: XSS PAYLOAD INJECTOR (Reflected + DOM)

Automated XSS payload injector with fallback to DOM-based triggers.

**Features**

* Injects into any URL with a parameter (e.g. `?q=1`)
* Rotates `<script>` payloads, onerror handlers, fetch+cookie grabbers
* Detects reflected payloads in HTML response
* Adds fallback DOM-based payload if no reflection is found
* Detects **duplicate 200 responses** for fake or honeypot behavior
* Logs successful hits to `loot/xss_hits.txt`

**Integration with Mini Scanner**
If you've run Module 6 (`Mini Scanner`), it saves a target list to:

```
loot/param_targets.txt
```

This list can be auto-loaded into Module 12 for rapid XSS injection across all discovered param endpoints 💉

---

## ADDITIONAL TIPS

* Inspect raw HTML snapshots to uncover hidden form fields, JavaScript traps, and backdoors.
* DIRB results depend on the site. Dead buckets or static pages may yield no hits.
* For advanced brute-forcing, use `ffuf`, `dirb`, or `gobuster` with custom wordlists.
* Explore redirects and forms with `curl -v`.
* Query phishing IPs on [https://shodan.io](https://shodan.io) for deeper reconnaissance.
* Check out **Phish Breaker** — an advanced companion toolkit.
  Repo: [https://github.com/ekomsSavior/phish\_breaker](https://github.com/ekomsSavior/phish_breaker)

---

## STAY TUNED

This project is under active development.

---

## DISCLAIMER

**PHISH\_HUNTER\_PRO is for ethical, legal use only.**

You must have explicit permission to test targets.
Use responsibly. You assume full liability for how you deploy this software.

---

## AUTHOR

Crafted with purpose by
**ek0ms savi0r**

GitHub → [https://github.com/ekomsSavior](https://github.com/ekomsSavior)
Instagram → [https://instagram.com/ekoms.is.my.savior](https://instagram.com/ekoms.is.my.savior)
Medium → [https://medium.com/@ekoms1/phish-hunter-pro-b3cc30041f91](https://medium.com/@ekoms1/phish-hunter-pro-b3cc30041f91)


