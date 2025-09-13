#!/usr/bin/env bash
#===============================================================
# DomainHunter v2.1 - ReconStrom (Improved)
# Author: Cyber Ghost (HackOps) - patched by Hinata
# Purpose: Subdomain/port/dir/http/vuln recon with safer handling
#===============================================================

set -o pipefail
shopt -s nocasematch

#----------------- COLORS -----------------
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
RESET="\e[0m"

#----------------- GLOBALS -----------------
SCRIPT_NAME="$(basename "$0")"
DOMAIN=""
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BASE_RESULTS_DIR="results"
TARGET_DIR=""

# preferred tools (we will warn if any missing)
REQUIRED_TOOLS=(subfinder nmap gobuster whatweb nikto curl)

# candidate wordlists (search through common locations)
CANDIDATE_WORDLISTS=(
  "/usr/share/wordlists/dirb/common.txt"
  "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
  "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt"
  "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
  "/data/data/com.termux/files/usr/share/wordlists/dirb/common.txt"
)

#----------------- HELP MENU -----------------
usage() {
    echo -e "${YELLOW}Usage: $SCRIPT_NAME <domain>${RESET}"
    echo
    echo "Example:"
    echo "  $SCRIPT_NAME example.com"
    exit 1
}

#----------------- UTIL -----------------
log() { printf "%b\n" "$*"; }
info() { log "${GREEN}[+]${RESET} $*"; }
warn() { log "${YELLOW}[!]${RESET} $*"; }
err()  { log "${RED}[!]${RESET} $*"; }

# find an available wordlist from candidates
find_wordlist() {
    for p in "${CANDIDATE_WORDLISTS[@]}"; do
        if [ -f "$p" ]; then
            echo "$p"
            return 0
        fi
    done
    # fallback: try locate common path
    if [ -f "./wordlists/common.txt" ]; then
        echo "./wordlists/common.txt"
        return 0
    fi
    return 1
}

# check tools but don't exit immediately; collect missing ones
check_tools() {
    local missing=()
    for t in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$t" >/dev/null 2>&1; then
            missing+=("$t")
        fi
    done
    if [ ${#missing[@]} -ne 0 ]; then
        warn "Missing tools: ${missing[*]}"
        warn "The script will try to run available modules; install missing tools for full functionality."
        warn "On Kali: sudo apt update && sudo apt install -y ${missing[*]}"
        warn "On Termux: pkg install <tool> (some tools may not be available on Termux)"
    fi
}

# create results directories
prepare_dirs() {
    mkdir -p "$BASE_RESULTS_DIR"
    TARGET_DIR="${BASE_RESULTS_DIR}/${DOMAIN}_${TIMESTAMP}"
    mkdir -p "$TARGET_DIR"
    info "Results will be saved to: $TARGET_DIR"
}

# trap ctrl+c
trap_ctrlc() {
    echo
    warn "Interrupted. Cleaning up and exiting."
    exit 1
}

#----------------- RECON MODULES -----------------

# Subdomain Enumeration
subdomain_enum() {
    info "Running Subdomain Enumeration..."
    if ! command -v subfinder >/dev/null 2>&1; then
        warn "subfinder not found — skipping subdomain enumeration."
        return 0
    fi
    # subfinder outputs unique subdomains, save to file
    subfinder -d "$DOMAIN" -silent | sort -u | tee "${TARGET_DIR}/subdomains.txt"
    info "Subdomains saved to ${TARGET_DIR}/subdomains.txt"
}

# Port Scanning
port_scan() {
    info "Running Port Scan (Top/service discovery)..."
    if ! command -v nmap >/dev/null 2>&1; then
        warn "nmap not found — skipping port scan."
        return 0
    fi
    # Fast scan for common ports then full if requested
    nmap -T4 -sV --top-ports 1000 -oN "${TARGET_DIR}/nmap_top1000.txt" "$DOMAIN"
    info "Top-1000 port scan saved to ${TARGET_DIR}/nmap_top1000.txt"
    # optional full port scan (commented out by default because it's slow)
    # nmap -T4 -p- --open -v "$DOMAIN" -oN "${TARGET_DIR}/nmap_allports.txt"
}

# helper: determine scheme (http/https)
detect_scheme() {
    # try https first (quiet), fallback to http
    if command -v curl >/dev/null 2>&1; then
        if curl -s -I -m 8 "https://${DOMAIN}" >/dev/null 2>&1; then
            echo "https"
            return
        fi
        if curl -s -I -m 6 "http://${DOMAIN}" >/dev/null 2>&1; then
            echo "http"
            return
        fi
    fi
    # default to http if unsure
    echo "http"
}

# Directory Bruteforce
dir_enum() {
    info "Running Directory Bruteforce..."
    if ! command -v gobuster >/dev/null 2>&1; then
        warn "gobuster not found — skipping directory brute force."
        return 0
    fi

    WL="$(find_wordlist || true)"
    if [ -z "$WL" ]; then
        warn "No wordlist found in common locations. Please install seclists or provide a wordlist at one of:"
        for p in "${CANDIDATE_WORDLISTS[@]}"; do echo "  $p"; done
        return 0
    fi

    SCHEME="$(detect_scheme)"
    info "Detected scheme: $SCHEME  (using gobuster with $WL)"
    gobuster dir -u "${SCHEME}://${DOMAIN}" -w "$WL" -o "${TARGET_DIR}/dirs.txt" -t 30 || warn "gobuster finished with non-zero status"
    info "Directories saved to ${TARGET_DIR}/dirs.txt"
}

# HTTP Headers & Tech Detection
http_info() {
    info "Fetching HTTP headers & technology detection..."
    # use whatweb if available, else fallback to curl headers
    if command -v whatweb >/dev/null 2>&1; then
        whatweb --log-brief="${TARGET_DIR}/whatweb.txt" "$DOMAIN" >/dev/null 2>&1 || warn "whatweb returned non-zero status"
        info "whatweb output saved to ${TARGET_DIR}/whatweb.txt"
    else
        warn "whatweb not found — saving HTTP headers with curl"
        if command -v curl >/dev/null 2>&1; then
            curl -sI "http://${DOMAIN}" | tee "${TARGET_DIR}/http_headers.txt"
            info "HTTP headers saved to ${TARGET_DIR}/http_headers.txt"
        else
            warn "curl not available either; cannot fetch HTTP info."
        fi
    fi
}

# Vulnerability Scan (basic)
vuln_scan() {
    info "Running basic Vulnerability Scan (nikto)..."
    if ! command -v nikto >/dev/null 2>&1; then
        warn "nikto not found — skipping vulnerability scan."
        return 0
    fi
    nikto -h "$DOMAIN" -output "${TARGET_DIR}/nikto.txt" || warn "nikto finished with non-zero status"
    info "Nikto results saved to ${TARGET_DIR}/nikto.txt"
}

#----------------- MENU -----------------
menu() {
    while true; do
        clear
        echo -e "${BLUE}==============================================================${RESET}"
        echo -e "${BLUE}                 🔥 DomainHunter v2.1 🔥${RESET}"
        echo -e "${BLUE}        Advanced Reconnaissance Automation Framework${RESET}"
        echo -e "${BLUE}==============================================================${RESET}"
        echo
        echo -e "${YELLOW}Target Domain: ${GREEN}$DOMAIN${RESET}"
        echo
        echo " [1] Subdomain Enumeration"
        echo " [2] Port Scanning"
        echo " [3] Directory Bruteforce"
        echo " [4] HTTP Info & Tech Detection"
        echo " [5] Vulnerability Scan (Nikto)"
        echo " [6] Run All (recommended)"
        echo " [0] Exit"
        echo
        read -r -p "Choose an option: " choice

        case "$choice" in
            1) subdomain_enum ;;
            2) port_scan ;;
            3) dir_enum ;;
            4) http_info ;;
            5) vuln_scan ;;
            6) subdomain_enum; port_scan; dir_enum; http_info; vuln_scan ;;
            0) info "Exiting..."; exit 0 ;;
            *) err "Invalid option. Try again." ;;
        esac

        echo
        read -r -p "Press Enter to continue..." dummy
    done
}

#----------------- MAIN -----------------
main() {
    trap 'trap_ctrlc' INT

    if [ $# -eq 0 ]; then
        usage
    fi

    DOMAIN="$1"
    prepare_dirs
    check_tools
    menu
}

main "$@"
