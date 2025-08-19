#!/bin/bash
#===============================================================
# ReconStrom - Advanced Reconnaissance Automation Tool
# Author : Cyber Ghost (HackOps)
#===============================================================

#----------------- COLORS -----------------
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
RESET="\e[0m"

#----------------- BANNER -----------------
banner() {
    clear
    echo -e "${BLUE}"
    echo "=============================================================="
    echo "                 🔥 ReconStrom v2.0 🔥"
    echo "        Advanced Reconnaissance Automation Framework"
    echo "=============================================================="
    echo -e "${RESET}"
}

#----------------- HELP MENU -----------------
usage() {
    echo -e "${YELLOW}Usage: $0 <domain>${RESET}"
    echo
    echo "Example:"
    echo "  $0 example.com"
    exit 1
}

#----------------- FUNCTIONS -----------------

# Check if a tool exists
check_tool() {
    command -v "$1" >/dev/null 2>&1 || { 
        echo -e "${RED}[!] $1 is not installed. Install it first.${RESET}"
        exit 1
    }
}

# Subdomain Enumeration
subdomain_enum() {
    echo -e "${GREEN}[+] Running Subdomain Enumeration...${RESET}"
    check_tool subfinder
    subfinder -d "$domain" -silent | tee results/subdomains.txt
    echo -e "${YELLOW}[*] Subdomains saved in results/subdomains.txt${RESET}"
}

# Port Scanning
port_scan() {
    echo -e "${GREEN}[+] Running Nmap Scan...${RESET}"
    check_tool nmap
    nmap -T4 -p- --open -v "$domain" -oN results/ports.txt
    echo -e "${YELLOW}[*] Port scan saved in results/ports.txt${RESET}"
}

# Directory Bruteforce
dir_enum() {
    echo -e "${GREEN}[+] Running Directory Bruteforce...${RESET}"
    check_tool gobuster
    gobuster dir -u "http://$domain" -w /usr/share/wordlists/dirb/common.txt -o results/dirs.txt
    echo -e "${YELLOW}[*] Directories saved in results/dirs.txt${RESET}"
}

# HTTP Headers & Tech Detection
http_info() {
    echo -e "${GREEN}[+] Fetching HTTP Headers & Technologies...${RESET}"
    check_tool whatweb
    whatweb "$domain" | tee results/http_info.txt
    echo -e "${YELLOW}[*] Info saved in results/http_info.txt${RESET}"
}

# Vulnerability Scan (basic)
vuln_scan() {
    echo -e "${GREEN}[+] Running Nikto Vulnerability Scan...${RESET}"
    check_tool nikto
    nikto -h "$domain" | tee results/vuln_scan.txt
    echo -e "${YELLOW}[*] Vulnerabilities saved in results/vuln_scan.txt${RESET}"
}

#----------------- MENU -----------------
menu() {
    while true; do
        banner
        echo -e "${YELLOW}Target Domain: ${GREEN}$domain${RESET}"
        echo
        echo " [1] Subdomain Enumeration"
        echo " [2] Port Scanning"
        echo " [3] Directory Bruteforce"
        echo " [4] HTTP Info & Tech Detection"
        echo " [5] Vulnerability Scan"
        echo " [6] Run All"
        echo " [0] Exit"
        echo
        read -p "Choose an option: " choice

        case $choice in
            1) subdomain_enum ;;
            2) port_scan ;;
            3) dir_enum ;;
            4) http_info ;;
            5) vuln_scan ;;
            6) subdomain_enum; port_scan; dir_enum; http_info; vuln_scan ;;
            0) echo -e "${RED}Exiting...${RESET}"; exit 0 ;;
            *) echo -e "${RED}[!] Invalid option. Try again.${RESET}" ;;
        esac
        echo -e "\nPress Enter to continue..."
        read
    done
}

#----------------- MAIN -----------------
if [ $# -eq 0 ]; then
    usage
fi

domain=$1
mkdir -p results

menu
