#!/usr/bin/env bash
#===============================================================
# DomainHunter v3.5 - Universal Kali & Termux Edition
# Author: Cyber Ghost 
# Organization: Hackops Academy 
#===============================================================

set -o pipefail

#----------------- UNIVERSAL COLORS -----------------
NC='\033[0m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'

#----------------- ENVIRONMENT DETECTION -----------------
IS_TERMUX=false
if [[ "$PREFIX" == *"/com.termux"* ]]; then
    IS_TERMUX=true
    BIN_PATH="$PREFIX/bin"
else
    IS_TERMUX=false
    BIN_PATH="/usr/local/bin"
fi

DOMAIN=$1
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
TARGET_DIR="results/${DOMAIN}_${TIMESTAMP}"

#----------------- DYNAMIC BANNER -----------------
draw_banner() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
 ________                        .__         ___ ___               __                
\______ \   ____   _____ _____  |__| ____  /   |   \ __ __  _____/  |_  ___________ 
 |    |  \ /  _ \ /     \\__  \ |  |/    \/    ~    \  |  \/    \   __\/ __ \_  __ \
 |    `   (  <_> )  Y Y  \/ __ \|  |   |  \    Y    /  |  /   |  \  | \  ___/|  | \/
/_______  /\____/|__|_|  (____  /__|___|  /\___|_  /|____/|___|  /__|  \___  >__|   
        \/             \/     \/        \/       \/            \/          \/        
EOF
    echo -e "${BLUE}  >> Environment: $([ "$IS_TERMUX" = true ] && echo "Termux (Mobile)" || echo "Linux (Kali/PC)")"
    echo -e "  >> Target: ${WHITE}${DOMAIN:-"None"}${NC}"
    echo -e "${BLUE}---------------------------------------------------------------${NC}"
}

#----------------- AUTO-INSTALLER ENGINE -----------------
install_deps() {
    echo -e "${YELLOW}[!] Starting Auto-Installer...${NC}"
    
    if [ "$IS_TERMUX" = true ]; then
        echo -e "${BLUE}[*] Updating Termux packages...${NC}"
        pkg update -y && pkg upgrade -y
        pkg install -y nmap curl git golang jq python whatweb
    else
        echo -e "${BLUE}[*] Updating Kali/Linux packages...${NC}"
        sudo apt update
        sudo apt install -y nmap curl git golang jq subfinder gobuster whatweb nikto
    fi

    # Install Go-based tools for Termux specifically
    if [ "$IS_TERMUX" = true ]; then
        echo -e "${BLUE}[*] Installing Go-tools for Termux...${NC}"
        export GOPATH=$HOME/go
        export PATH=$PATH:$GOPATH/bin
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        go install -v github.com/OJ/gobuster/v3@latest
        # Link to bin for easy access
        cp $HOME/go/bin/subfinder $PREFIX/bin/ 2>/dev/null
        cp $HOME/go/bin/gobuster $PREFIX/bin/ 2>/dev/null
    fi
    
    echo -e "${GREEN}[✔] All dependencies installed.${NC}"
    sleep 2
}

#----------------- CORE FUNCTIONS -----------------
run_subdomains() {
    echo -e "${GREEN}[+] Running Subfinder...${NC}"
    subfinder -d "$DOMAIN" -silent -o "${TARGET_DIR}/subs.txt"
}

run_nmap() {
    echo -e "${GREEN}[+] Running Nmap (Fast Scan)...${NC}"
    nmap -T4 -F "$DOMAIN" -oN "${TARGET_DIR}/nmap.txt"
}

run_gobuster() {
    # Auto-locate wordlist based on OS
    if [ "$IS_TERMUX" = true ]; then
        WL="$HOME/common.txt"
        [ ! -f "$WL" ] && curl -s https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt -o "$WL"
    else
        WL="/usr/share/wordlists/dirb/common.txt"
    fi
    
    echo -e "${GREEN}[+] Running Gobuster with: $WL${NC}"
    gobuster dir -u "http://$DOMAIN" -w "$WL" -z -o "${TARGET_DIR}/dirs.txt"
}

#----------------- MENU SYSTEM -----------------
main_menu() {
    while true; do
        draw_banner
        echo -e "  ${WHITE}[1]${NC} Full Recon Scan (All Tools)"
        echo -e "  ${WHITE}[2]${NC} Subdomain Enumeration Only"
        echo -e "  ${WHITE}[3]${NC} Port Scan (Nmap)"
        echo -e "  ${WHITE}[4]${NC} Directory Bruteforce"
        echo -e "  ${CYAN}[I]${NC} Install/Update Dependencies"
        echo -e "  ${RED}[0]${NC} Exit"
        echo -e "${BLUE}---------------------------------------------------------------${NC}"
        read -p "Selection > " opt

        case $opt in
            1) mkdir -p "$TARGET_DIR"; run_subdomains; run_nmap; run_gobuster ;;
            2) mkdir -p "$TARGET_DIR"; run_subdomains ;;
            3) mkdir -p "$TARGET_DIR"; run_nmap ;;
            4) mkdir -p "$TARGET_DIR"; run_gobuster ;;
            i|I) install_deps ;;
            0) exit 0 ;;
            *) echo -e "${RED}Invalid Option${NC}"; sleep 1 ;;
        esac
        echo -e "\n${YELLOW}Task complete. Results in: $TARGET_DIR${NC}"
        read -p "Press Enter to continue..."
    done
}

#----------------- START -----------------
if [ -z "$1" ]; then
    draw_banner
    echo -e "${RED}Usage: ./DomainHunter.sh <target.com>${NC}"
    exit 1
fi

main_menu
