# PHISH_HUNTER_PRO

Advanced phishing investigation and disruption toolkit written in Python.

PHISH_HUNTER_PRO is a modular Python-based anti-phishing reconnaissance and disruption toolkit.  

Created by ekomsSavior, it is designed for security researchers, cyber defenders, and OSINT specialists to investigate and take action against phishing infrastructure.

It performs deep web page analysis, login page spam, open port scanning, SSL certificate inspection, metadata extraction, Shodan lookups, VirusTotal enrichment, and more.

---

## INSTALLATION

Clone the repository

    git clone https://github.com/ekomsSavior/PHISH_HUNTER_PRO.git
    cd PHISH_HUNTER_PRO

Install the necessary system dependencies

    sudo apt update && sudo apt install tor dirb nmap curl python3-pip python3-requests -y

---

## RUNNING THE TOOL

Start Tor manually before launching the spammer (do this **every time** before using PHISH_HUNTER_PRO)

    sudo service tor start

Then launch the tool

    python3 cli.py

You'll be presented with a menu

    [1] Scan Domain           – WHOIS, DNS headers, basic fingerprinting  
    [2] Spam Login Page       – Sends fake logins through Tor + proxy  
    [3] Deep Recon            – Full phishing investigation pipeline

---

## API KEY SETUP

This tool supports **Shodan** and **VirusTotal**.

Edit the top of `deep_recon.py` to insert your API keys

    SHODAN_API_KEY = "your_key_here"
    VT_API_KEY = "your_key_here"

---

## WHAT DEEP RECON MODULE DOES

- Follows and logs HTTP redirects  
- Analyzes SSL certificates via OpenSSL  
- Extracts metadata: inputs, iframes, scripts, emails, meta tags  
- Saves a snapshot and raw HTML of the target  
- Performs form discovery with curl and grep  
- Runs a full `nmap` scan (top 1000 ports with version detection)  
- Queries Shodan for IP intelligence  
- Looks up VirusTotal results on the domain  
- Finishes with a `dirb` brute-force directory scan (**600s timeout – this can take up to 10 minutes**)

All output is saved to the `reports/` folder.

---

## ADDITIONAL TIPS FOR USERS

- Run `curl -s https://target.com/path -o snapshot.html` to save a live view of the phishing page  
- Run `curl -v https://target.com/path` to see request/response data and understand how the page behaves  
- Take the IP of a phishing domain and search it directly on [https://shodan.io](https://shodan.io) for deeper recon  
- Use `ffuf`, `gobuster`, or `dirb` with alternate wordlists for extended brute-forcing  
- Open the HTML snapshot saved by Deep Recon to explore forms, links, or other signs of malicious activity

---

## SPAMMER MODULE

Use the built-in spammer to disrupt phishing login forms with fake credentials.  
It supports Tor, randomized user-agents, and proxy rotation.

**Reminder:** You must manually start Tor (`sudo service tor start`) before running the spammer.

For slower, script-based spam (ideal for scam pages with minimal protection), refer to the original Bash version of Phish Hunter.

---

## STAY TUNED

This is an evolving project. Future updates will include deeper automation, smarter evasion, visual dashboards, and expanded modules. 

Bookmark this repo or follow me to stay up to date.

Want to support the ethical hacker community?  
Submit a pull request or connect with me.

GitHub: https://github.com/ekomsSavior  
Instagram: https://instagram.com/ekoms.is.my.savior  

Together we are stronger. Let’s make scammers afraid again — and protect the innocent they target.

---

## DISCLAIMER

Phish Hunter PRO is for **legal and ethical use only**.  

Use this tool only on domains you have permission to investigate.

By using this software, you accept full responsibility for its use and release the author from all liability related to misuse.

---

## AUTHOR

Created with intent, precision, and purpose by

**ek0ms savi0r** – https://github.com/ekomsSavior
