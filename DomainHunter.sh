#!/usr/bin/env bash
# ============================================================================
# DomainHunter 2.0 - Advanced Subdomain & Recon Tool
# Author: Lucky (Cyber Ghost)
# GitHub: https://github.com/yourusername/DomainHunter
# License: MIT
# ============================================================================
set -Eeuo pipefail
IFS=$'\n\t'

# ----------------------------- Colors & UI ----------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'
hr() { printf "${CYAN}%*s${RESET}\n" "$(tput cols)" | tr ' ' '─'; }
info() { echo -e "${CYAN}[i]${RESET} $*"; }
ok()   { echo -e "${GREEN}[✔]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
err()  { echo -e "${RED}[✘]${RESET} $*"; }

cleanup() { trap - EXIT INT; }; trap cleanup EXIT INT

# ----------------------------- Banner ---------------------------------------
clear
cat << 'EOF'
@@@@@@@    @@@@@@   @@@@@@@@@@    @@@@@@   @@@  @@@  @@@  @@@  @@@  @@@  @@@  @@@  @@   @@@@@@@  @@@@@@@@  @@@@@@@   
@@@@@@@@  @@@@@@@@  @@@@@@@@@@@  @@@@@@@@  @@@  @@@@ @@@  @@@  @@@  @@@  @@@  @@@@ @@@  @@@@@@@  @@@@@@@@  @@@@@@@@  
@@!  @@@  @@!  @@@  @@! @@! @@!  @@!  @@@  @@!  @@!@!@@@  @@!  @@@  @@!  @@@  @@!@!@@@    @@!    @@!       @@!  @@@  
!@!  @!@  !@!  @!@  !@! !@! !@!  !@!  @!@  !@!  !@!!@!@!  !@!  @!@  !@!  @!@  !@!!@!@!    !@!    !@!       !@!  @!@  
@!@  !@!  @!@  !@!  @!! !!@ @!@  @!@!@!@!  !!@  @!@ !!@!  @!@!@!@!  @!@  !@!  @!@ !!@!    @!!    @!!!:!    @!@!!@!   
!@!  !!!  !@!  !!!  !@!   ! !@!  !!!@!!!!  !!!  !@!  !!!  !!!@!!!!  !@!  !!!  !@!  !!!    !!!    !!!!!:    !!@!@!    
!!:  !!!  !!:  !!!  !!:     !!:  !!:  !!!  !!:  !!:  !!!  !!:  !!!  !!:  !!!  !!:  !!!    !!:    !!:       !!: :!!   
:!:  !:!  :!:  !:!  :!:     :!:  :!:  !:!  :!:  :!:  !:!  :!:  !:!  :!:  !:!  :!:  !:!    :!:    :!:       :!:  !:!  
 :::: ::  ::::: ::  :::     ::   ::   :::   ::   ::   ::  ::   :::  ::::: ::   ::   ::     ::     :: ::::  ::   :::  
:: :  :    : :  :    :      :     :   : :  :    ::    :    :   : :   : :  :   ::    :      :     : :: ::    :   : :  
EOF

printf "${BOLD}${BLUE}%s${RESET}\n" "DomainHunter — Advanced Subdomain & Recon Tool"
hr
# ----------------------------- Globals --------------------------------------
PLATFORM="$(uname -o 2>/dev/null || uname -s)"
DATE_TAG="$(date +%Y%m%d-%H%M%S)"
WORKDIR="DomainHunter-${DATE_TAG}"
LOGFILE="${WORKDIR}/domainhunter.log"
mkdir -p "$WORKDIR"{,/shots,/reports}
touch "$LOGFILE"
exec > >(tee -a "$LOGFILE") 2>&1

input_domain=""

# ----------------------------- Dependency Management ------------------------
REQUIRED=(subfinder dnsx httpx naabu whois dig jq)
OPTIONAL=(amass assetfinder gowitness eyewitness katana waybackurls nmap anew)
have() { command -v "$1" >/dev/null 2>&1; }

auto_install_all() {
    info "Installing dependencies..."
    if have apt; then
        sudo apt update
        sudo apt install -y git curl jq whois nmap dnsutils python3 golang || true
    fi
    declare -A go_tools=(
        [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        [httpx]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
        [dnsx]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        [naabu]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        [katana]="github.com/projectdiscovery/katana/cmd/katana@latest"
        [gowitness]="github.com/sensepost/gowitness@latest"
        [waybackurls]="github.com/tomnomnom/waybackurls@latest"
        [anew]="github.com/tomnomnom/anew@latest"
    )
    for tool in "${!go_tools[@]}"; do
        if ! have $tool; then
            info "Installing $tool via Go..."
            go install -v "${go_tools[$tool]}" || warn "$tool installation failed!"
        fi
    done
    export PATH=$PATH:$HOME/go/bin
    ok "Dependencies installed."
}

check_deps() {
    local missing=()
    for t in "${REQUIRED[@]}"; do have "$t" || missing+=("$t"); done
    if ((${#missing[@]})); then
        warn "Missing required tools: ${missing[*]}"
        echo -en "${YELLOW}Install all missing dependencies automatically? [y/N]: ${RESET}"
        read -r ans || true
        [[ "${ans:-N}" =~ ^[Yy]$ ]] && auto_install_all || { err "Install required tools manually"; exit 1; }
    fi
}

# ----------------------------- Files ----------------------------------------
subdomains_file() { echo "${WORKDIR}/${input_domain}.subdomains.txt"; }
resolved_file()   { echo "${WORKDIR}/${input_domain}.resolved.txt"; }
live_file()       { echo "${WORKDIR}/${input_domain}.live.txt"; }
endpoints_file()  { echo "${WORKDIR}/${input_domain}.endpoints.txt"; }
secrets_file()    { echo "${WORKDIR}/${input_domain}.secrets.txt"; }
ips_file()        { echo "${WORKDIR}/${input_domain}.ips.txt"; }
whois_file()      { echo "${WORKDIR}/reports/${input_domain}.whois.txt"; }
dns_file()        { echo "${WORKDIR}/reports/${input_domain}.dns.txt"; }
ports_file()      { echo "${WORKDIR}/${input_domain}.ports.txt"; }

# ----------------------------- Core Functions --------------------------------
prompt_domain() {
    if [[ -z "${input_domain}" ]]; then
        echo -en "${BOLD}Enter target domain (example.com): ${RESET}"
        read -r input_domain
        [[ -n "$input_domain" ]] || { err "No domain provided"; exit 1; }
    fi
}

run_subfinder() {
    prompt_domain; hr
    info "Running subdomain enumeration..."
    subfinder -d "$input_domain" -all -silent | sort -u | tee "$(subdomains_file)"
    ok "Subdomains saved: $(subdomains_file)"
}

resolve_subdomains() {
    prompt_domain; hr
    info "Resolving subdomains..."
    dnsx -l "$(subdomains_file)" -silent -a | tee "$(resolved_file)"
    awk '{print $2}' "$(resolved_file)" | tr ',' '\n' | sed 's/[\[\]]//g' | sort -u > "$(ips_file)"
    ok "Resolved IPs saved: $(ips_file)"
}

check_live_http() {
    prompt_domain; hr
    info "🔍 Checking for live HTTP(s) servers..."

    # Validate subdomains file
    if [[ ! -s "$(subdomains_file)" ]]; then
        error "No subdomains found! Run subdomain enumeration first."
        return 1
    fi

    # Run httpx with better output
    httpx -l "$(subdomains_file)" \
        -title -status-code -tech-detect -web-server -follow-redirects -timeout 5 -threads 50 \
        -mc 200,301,302,307,401,403 \
        -silent | tee "$(live_file)"

    if [[ -s "$(live_file)" ]]; then
        ok "✅ Live hosts saved to: $(live_file)"
        info "📊 Summary of results:"
        awk '{print "• " $0}' "$(live_file)"
    else
        warn "⚠ No live hosts found."
    fi
}


screenshot_hosts() {
    prompt_domain; hr
    info "Taking screenshots..."
    cut -d ' ' -f1 "$(live_file)" > "${WORKDIR}/_urls.txt"
    if have gowitness; then
        gowitness file -f "${WORKDIR}/_urls.txt" -P "${WORKDIR}/shots" --timeout 15 --disable-logging || true
    elif have eyewitness; then
        eyewitness --web --threads 5 -f "${WORKDIR}/_urls.txt" -d "${WORKDIR}/shots" || true
    else
        warn "No screenshot tool found."
    fi
    ok "Screenshots saved: ${WORKDIR}/shots"
}

collect_endpoints() {
    prompt_domain; hr
    info "Collecting endpoints..."
    : > "$(endpoints_file)"
    cut -d ' ' -f1 "$(live_file)" > "${WORKDIR}/_urls.txt"
    [[ -s "${WORKDIR}/_urls.txt" ]] || { warn "No live hosts found"; return; }
    [[ $(have katana) ]] && katana -list "${WORKDIR}/_urls.txt" -silent -em js,json,txt | sort -u | tee -a "$(endpoints_file)"
    [[ $(have waybackurls) ]] && cat "${WORKDIR}/_urls.txt" | waybackurls | sort -u | tee -a "$(endpoints_file)"
    sort -u "$(endpoints_file)" -o "$(endpoints_file)"
    ok "Endpoints saved: $(endpoints_file)"
}

fast_port_scan() {
    prompt_domain; hr
    info "Running TCP scan..."
    [[ -s "$(ips_file)" ]] || resolve_subdomains
    [[ -s "$(ips_file)" ]] || { warn "No IPs found"; return; }
    naabu -list "$(ips_file)" -top-ports 1000 -silent | tee "$(ports_file)"
    ok "Open ports saved: $(ports_file)"
    if have nmap; then
        echo -en "${YELLOW}Run nmap service/version scan? [y/N]: ${RESET}"
        read -r ans || true
        [[ "${ans:-N}" =~ ^[Yy]$ ]] && while read -r host; do
            ports=$(grep "^$host:" "$(ports_file)" | awk -F: '{print $2}' | paste -sd, -)
            [[ -n "$ports" ]] && nmap -sV -Pn -p "$ports" "$host" -oN "${WORKDIR}/reports/${host}.nmap.txt"
        done < "$(ips_file)"
    fi
}

whois_dns_report() {
    prompt_domain; hr
    info "Collecting WHOIS & DNS records..."
    whois "$input_domain" > "$(whois_file)" 2>/dev/null || true
    {
        echo "=== A ==="; dig +short A "$input_domain"
        echo "=== AAAA ==="; dig +short AAAA "$input_domain"
        echo "=== NS ==="; dig +short NS "$input_domain"
        echo "=== MX ==="; dig +short MX "$input_domain"
        echo "=== TXT ==="; dig +short TXT "$input_domain"
        echo "=== CNAME ==="; dig +short CNAME "$input_domain"
    } | tee "$(dns_file)"
    ok "WHOIS/DNS saved: $(whois_file) & $(dns_file)"
}

pipeline_all() {
    prompt_domain
    run_subfinder
    resolve_subdomains
    check_live_http
    screenshot_hosts
    collect_endpoints
    fast_port_scan
    whois_dns_report
    ok "Pipeline complete. Workspace: ${WORKDIR}"
}

# ----------------------------- Menu -----------------------------------------
menu() {
    hr
    echo -e "${BOLD}${CYAN}====================[ DomainHunter Menu ]====================${RESET}"
    echo -e "${YELLOW}[1] Subdomain Enumeration${RESET}"
    echo -e "${YELLOW}[2] Live HTTP Probing${RESET}"
    echo -e "${YELLOW}[3] Screenshots${RESET}"
    echo -e "${YELLOW}[4] Endpoints Scan${RESET}"
    echo -e "${YELLOW}[5] Fast Port Scan${RESET}"
    echo -e "${YELLOW}[6] WHOIS & DNS${RESET}"
    echo -e "${YELLOW}[7] Full Pipeline${RESET}"
    echo -e "${YELLOW}[8] Set/Change Target Domain${RESET}"
    echo -e "${YELLOW}[9] Exit${RESET}"
    hr
}

set_domain_interactive() { input_domain=""; prompt_domain; ok "Target set: ${input_domain}"; }

# ----------------------------- Main -----------------------------------------
check_deps
while true; do
    menu
    [[ -n "$input_domain" ]] && echo -e "${BOLD}Current target:${RESET} ${input_domain}"
    echo -en "${BOLD}Choose option: ${RESET}"; read -r choice || true
    case "${choice:-}" in
        1) run_subfinder;;
        2) check_live_http;;
        3) screenshot_hosts;;
        4) collect_endpoints;;
        5) fast_port_scan;;
        6) whois_dns_report;;
        7) pipeline_all;;
        8) set_domain_interactive;;
        9) ok "Exiting"; exit 0;;
        *) warn "Invalid choice";;
    esac
done
