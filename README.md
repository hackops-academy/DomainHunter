# 🌐 DomainHunter
_A Fast, Professional Subdomain & Recon Tool for Kali Linux and Termux_

![banner](https://img.shields.io/badge/Made%20By-HackOps%20Academy-%23purple) 
![Shell](https://img.shields.io/badge/Made%20with-Bash-blue)
![Status](https://img.shields.io/badge/Status-Active-success)
![PRs](https://img.shields.io/badge/PRs-welcome-brightgreen)

> **DomainHunter** is a lightweight, maintenance-friendly reconnaissance helper for Kali Linux and Termux.
It provides a simple TUI (terminal user interface) to run common reconnaissance primitives and save organized, timestamped results per target. DomainHunter is intended as a pragmatic wrapper around commonly-used recon tools — not a replacement for a full pentest suite

---

## Output Layer
All artifacts are stored under:
```bash
results/<target>_<YYYYMMDD_HHMMSS>/
```
Typical files produced (if corresponding tools are installed):

-subdomains.txt — subfinder

-nmap_top1000.txt — nmap summary

-dirs.txt — gobuster results

-whatweb.json or whatweb.txt — whatweb output / curl headers

-nikto.txt — nikto results

---



## 🔧 Installation

```bash
git clone https://github.com/hackops-academy/DomainHunter
cd DomainHunter
chmod +x DomainHunter.sh
```


## Usages

**Starting the tool**
```bash
./DomainHunter.sh (Domain Name)
```

## Menu Options
```bash


 ________                        .__         ___ ___               __
\______ \   ____   _____ _____  |__| ____  /   |   \ __ __  _____/  |_  ___________
 |    |  \ /  _ \ /     \\__  \ |  |/    \/    ~    \  |  \/    \   __\/ __ \_  __ \
 |    `   (  <_> )  Y Y  \/ __ \|  |   |  \    Y    /  |  /   |  \  | \  ___/|  | \/
/_______  /\____/|__|_|  (____  /__|___|  /\___|_  /|____/|___|  /__|  \___  >__|
        \/             \/     \/        \/       \/            \/          \/
  >> Environment: Termux (Mobile)
  >> Target: target.com
---------------------------------------------------------------
  [1] Full Recon Scan (All Tools)
  [2] Subdomain Enumeration Only
  [3] Port Scan (Nmap)
  [4] Directory Bruteforce
  [I] Install/Update Dependencies
  [0] Exit
---------------------------------------------------------------
Selection >
```





