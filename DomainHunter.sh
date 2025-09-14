#!/usr/bin/env bash
#===============================================================
# DomainHunter v2.2 - ReconStorm (Improved + Auto-Installer)
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
REQUIRED_TOOLS=(subfinder nmap gobuster whatweb nikto curl jq git)

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

#----------------- AUTO INSTALLER -----------------
bootstrap_tools() {
    REQUIRED_TOOLS=(subfinder nmap gobuster whatweb nikto curl jq git)
    GO_TOOLS=(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/OJ/gobuster/v3@latest"
    )

    IS_TERMUX=false
    PKG_MANAGER=""
    SUDO_CMD=""

    if [ -n "$PREFIX" ] && echo "$PREFIX" | grep -q "com.termux"; then
        IS_TERMUX=true
        PKG_MANAGER="pkg"
    elif command -v apt >/dev/null 2>&1; then
        PKG_MANAGER="apt"
        SUDO_CMD="sudo"
    elif command -v apt-get >/dev/null 2>&1; then
        PKG_MANAGER="apt-get"
        SUDO_CMD="sudo"
    fi

    info "Bootstrapping tools for DomainHunter (env: ${PKG_MANAGER:-unknown})"

    install_system_pkgs() {
        if [ "$PKG_MANAGER" = "apt" ] || [ "$PKG_MANAGER" = "apt-get" ]; then
            ${SUDO_CMD} ${PKG_MANAGER} update -y
            ${SUDO_CMD} ${PKG_MANAGER} install -y curl jq nmap git golang gobuster whatweb nikto seclists || true
        elif [ "$PKG_MANAGER" = "pkg" ]; then
            pkg update -y
            pkg install -y curl jq nmap git golang || true
        fi
    }

    ensure_go() {
        if ! command -v go >/dev/null 2>&1; then
            warn "Go not found, attempting to install..."
            [ "$PKG_MANAGER" = "apt" ] && ${SUDO_CMD} apt install -y golang || true
            [ "$PKG_MANAGER" = "pkg" ] && pkg install -y golang || true
        fi
        command -v go >/dev/null 2>&1
    }

    add_go_path() {
        GOPATH="${GOPATH:-$HOME/go}"
        GOBIN="$GOPATH/bin"
        export PATH="$GOBIN:$PATH"
        mkdir -p "$GOBIN"
    }

    install_go_tools() {
        ensure_go || return
        add_go_path
        for mod in "${GO_TOOLS[@]}"; do
            go install "$mod" || warn "Failed installing $mod"
        done
    }

    install_system_pkgs
    install_go_tools

    echo
    info "Final tool availability:"
    for t in "${REQUIRED_TOOLS[@]}"; do
        if command -v "$t" >/dev/null 2>&1; then
            echo -e "  ${GREEN}[OK]${RESET} $t -> $(command -v "$t")"
        else
            echo -e "  ${RED}[MISSING]${RESET} $t"
        fi
    done
    echo
}

#----------------- WORDLIST -----------------
find_wordlist() {
    for p in "${CANDIDATE_WORDLISTS[@]}"; do
        [ -f "$p" ] && { echo "$p"; return 0; }
    done
    [ -f "./wordlists/common.txt" ] && { echo "./wordlists/common.txt"; return 0; }
    return 1
}

check_tools() {
    local missing=()
    for t in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$t" >/dev/null 2>&1; then
            missing+=("$t")
        fi
    done
    [ ${#missing[@]} -ne 0 ] && warn "Missing: ${missing[*]}"
}

prepare_dirs() {
    mkdir -p "$BASE_RESULTS_DIR"
    TARGET_DIR="${BASE_RESULTS_DIR}/${DOMAIN}_${TIMESTAMP}"
    mkdir -p "$TARGET_DIR"
    info "Results will be saved to: $TARGET_DIR"
}

trap_ctrlc() {
    echo; warn "Interrupted. Exiting."
    exit 1
}

#----------------- RECON MODULES -----------------
subdomain_enum() {
    info "Running Subdomain Enumeration..."
    command -v subfinder >/dev/null 2>&1 || { warn "subfinder not found"; return; }
    subfinder -d "$DOMAIN" -silent | sort -u | tee "${TARGET_DIR}/subdomains.txt"
}

port_scan() {
    info "Running Port Scan..."
    command -v nmap >/dev/null 2>&1 || { warn "nmap not found"; return; }
    nmap -T4 -sV --top-ports 1000 -oN "${TARGET_DIR}/nmap_top1000.txt" "$DOMAIN"
}

detect_scheme() {
    if command -v curl >/dev/null 2>&1; then
        curl -s -I -m 8 "https://${DOMAIN}" >/dev/null 2>&1 && { echo "https"; return; }
        curl -s -I -m 6 "http://${DOMAIN}" >/dev/null 2>&1 && { echo "http"; return; }
    fi
    echo "http"
}

dir_enum() {
    info "Running Directory Bruteforce..."
    command -v gobuster >/dev/null 2>&1 || { warn "gobuster not found"; return; }
    WL="$(find_wordlist || true)"
    [ -z "$WL" ] && { warn "No wordlist found"; return; }
    SCHEME="$(detect_scheme)"
    gobuster dir -u "${SCHEME}://${DOMAIN}" -w "$WL" -o "${TARGET_DIR}/dirs.txt" -t 30
}

http_info() {
    info "Fetching HTTP info..."
    if command -v whatweb >/dev/null 2>&1; then
        whatweb --log-brief="${TARGET_DIR}/whatweb.txt" "$DOMAIN" >/dev/null 2>&1
    elif command -v curl >/dev/null 2>&1; then
        curl -sI "http://${DOMAIN}" | tee "${TARGET_DIR}/http_headers.txt"
    fi
}

vuln_scan() {
    info "Running Vulnerability Scan..."
    command -v nikto >/dev/null 2>&1 || { warn "nikto not found"; return; }
    nikto -h "$DOMAIN" -output "${TARGET_DIR}/nikto.txt"
}

#----------------- MENU -----------------
menu() { while true; do 
clear 
echo -e "${BLUE}==============================================================${RESET}"
echo -e "${BLUE}                     🔥 DomainHunter v2.1 🔥${RESET}" 
echo -e "${BLUE}        Advanced Reconnaissance Automation Framework${RESET}"
echo -e "${BLUE}==============================================================${RESET}"
echo
        echo " [1] Subdomain Enumeration"
        echo " [2] Port Scanning"
        echo " [3] Directory Bruteforce"
        echo " [4] HTTP Info & Tech Detection"
        echo " [5] Vulnerability Scan "
        echo " [6] Run All"
        echo " [0] Exit"
        echo
        read -r -p "Choose: " choice
        case "$choice" in
            1) subdomain_enum ;;
            2) port_scan ;;
            3) dir_enum ;;
            4) http_info ;;
            5) vuln_scan ;;
            6) subdomain_enum; port_scan; dir_enum; http_info; vuln_scan ;;
            0) info "Exiting..."; exit 0 ;;
            *) err "Invalid option." ;;
        esac
        echo; read -r -p "Press Enter..." dummy
    done
}

#----------------- MAIN -----------------
main() {
    trap 'trap_ctrlc' INT
    [ $# -eq 0 ] && usage
    DOMAIN="$1"
    prepare_dirs
    bootstrap_tools
    check_tools
    menu
}

main "$@"
