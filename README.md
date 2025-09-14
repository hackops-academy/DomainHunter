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





