# 🌐 DomainHunter
_A Fast, Professional Subdomain & Recon Tool for Kali Linux and Termux_


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

## 📦 Requirements

**Required**
- `subfinder` · `dnsx` · `httpx` · `naabu` · `whois` · `dig` (dnsutils) · `jq`

**Optional (recommended)**
- `gowitness` (or `eyewitness`) · `katana` · `waybackurls` · `nmap` · `amass` · `assetfinder` · `anew`

> DomainHunter detects missing tools and offers a best-effort installer (Kali/Go). Termux users should install Go and use `go install` for the latest binaries.

---

## 🔧 Installation

```bash
git clone https://github.com/yourusername/DomainHunter.git
cd DomainHunter
chmod +x domainhunter.sh
```

## Installing Dependencies

**Kali(APT)**






