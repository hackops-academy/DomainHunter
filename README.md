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
git clone https://github.com/hackops-academy/DomainHunter
cd DomainHunter
chmod +x DomainHunter.sh
```

## Installing Dependencies

**Kali(APT)**
```bash
sudo apt update && sudo apt install -y subfinder httpx-toolkit dnsx naabu whois dnsutils jq nmap
```

**GO(Latest Builds)
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/sensepost/gowitness@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/tomnomnom/anew@latest
```

**Termux**
```bash
pkg update && pkg install -y golang python whois dnsutils jq nmap git
# then use the Go installs above (ensure $GOPATH/bin is in PATH)
```

## Usages

**Starting the tool**
```bash
./DomainHunter.sh
```

## Menu Options

1. Subdomain Enumeration (subfinder)

2. Live HTTP Probing (httpx with status, title, tech)

3. Screenshots (gowitness/eyewitness)

4. Endpoints + Secrets (katana/waybackurls + regex check)

5. Fast Port Scan (naabu → optional targeted nmap -sV)

6. WHOIS & DNS Report (whois + dig)

7. Full Pipeline (1→6)

8. Set/Change Target Domain (To choose the target and starting the tool)

9. Exit


## Output Structure 

```bash
DomainHunter-YYYYMMDD-HHMMSS/
├─ <domain>.subdomains.txt
├─ <domain>.resolved.txt
├─ <domain>.live.txt
├─ <domain>.endpoints.txt
├─ <domain>.secrets.txt
├─ <domain>.ips.txt
├─ <domain>.ports.txt
├─ shots/                 # screenshots (if gowitness/eyewitness installed)
├─ reports/
│  ├─ <domain>.whois.txt
│  ├─ <domain>.dns.txt
│  └─ <host>.nmap.txt     # when nmap service scan is selected
└─ domainhunter.log       # full session log
```





