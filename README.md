# 🌐 DomainHunter
_A Fast, Professional Subdomain & Recon Tool for Kali Linux and Termux_

![banner](https://img.shields.io/badge/Made%20By-HackOps%20Academy-%23purple) 
![Shell](https://img.shields.io/badge/Made%20with-Bash-blue)
![Status](https://img.shields.io/badge/Status-Active-success)
![PRs](https://img.shields.io/badge/PRs-welcome-brightgreen)

> **DomainHunter** automates subdomain discovery, DNS resolution, live host probing, screenshots, endpoint crawling, lightweight secret hunting, port scanning, and WHOIS/DNS reporting — all from a polished TUI menu with logs and a timestamped workspace.

---

## ✨ Features

- **Subdomain Enumeration** — Passive + recursive (`subfinder`)  
- **DNS Resolution** — Resolve to A/AAAA & collect unique IPs (`dnsx`)  
- **Live Host Probing** — Status codes, titles, tech detection (`httpx`)  
- **Screenshots** — Web previews of live hosts (`gowitness` / fallback `eyewitness`)  
- **Endpoints + Secrets** — Crawl (`katana`/`waybackurls`) + regex-based secret hits  
- **Fast Port Scan** — Top ports with `naabu`, optional targeted `nmap -sV`  
- **WHOIS & DNS Report** — WHOIS + A/AAAA/NS/MX/TXT/CNAME dig reports  
- **Full Pipeline Mode** — One option runs everything end-to-end  
- **Great UX** — Color menu, ASCII banner, safe error handling, detailed logs



---



## 🔧 Installation

```bash
git clone https://github.com/hackops-academy/DomainHunter
cd DomainHunter
chmod +x DomainHunter.sh
```



**Termux**
```bash
pkg update && pkg install -y golang python whois dnsutils jq nmap git
# then use the Go installs above (ensure $GOPATH/bin is in PATH)
```

## Usages

**Starting the tool**
```bash
./DomainHunter.sh (Domain Name)
```

## Menu Options
```bash

        ==============================================================
                         🔥 DomainHunter v2.1 🔥
            Advanced Reconnaissance Automation Framework
        ==============================================================

         [1] Subdomain Enumeration
         [2] Port Scanning
         [3] Directory Bruteforce
         [4] HTTP Info & Tech Detection
         [5] Vulnerability Scan 
         [6] Run All (recommended)
         [0] Exit
```





