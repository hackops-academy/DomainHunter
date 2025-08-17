#!/usr/bin/env bash
# ============================================================================
# DomainHunter - Advanced Subdomain & Recon Tool (final)
# Author: Lucky (Cyber Ghost)
# GitHub: https://github.com/yourusername/DomainHunter
# License: MIT
# ============================================================================
set -Eeuo pipefail
IFS=$'\n\t'

# ----------------------------- UI helpers -----------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'
hr()  { printf "${CYAN}%*s${RESET}\n" "$(tput cols 2>/dev/null || echo 80)" | tr ' ' '─'; }
info(){ echo -e "${CYAN}[i]${RESET} $*"; }
ok()  { echo -e "${GREEN}[✔]${RESET} $*"; }
warn(){ echo -e "${YELLOW}[!]${RESET} $*"; }
err() { echo -e "${RED}[✘]${RESET} $*"; }

cleanup() { trap - EXIT INT; }
trap cleanup EXIT INT

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
printf "${BOLD}${BLUE}%s${RESET}\n" "Made by HackOps Academy"
hr
# ----------------------------- Globals -------------------------------------
DATE_TAG="$(date +%Y%m%d-%H%M%S)"
WORKDIR="DomainHunter-${DATE_TAG}"
LOGFILE="${WORKDIR}/domainhunter.log"
mkdir -p "$WORKDIR"{,/shots,/reports}
: > "$LOGFILE"
exec > >(tee -a "$LOGFILE") 2>&1

input_domain=""

# ----------------------------- Dependencies --------------------------------
REQUIRED=(subfinder dnsx httpx naabu whois dig jq)
OPTIONAL=(amass assetfinder gowitness eyewitness katana waybackurls nmap anew)
have() { command -v "$1" >/dev/null 2>&1; }

# Attempt to install missing deps (best-effort; asks user)
auto_install_all() {
  info "Auto-install: installing prerequisites (may ask for sudo)..."
  if have apt; then
    sudo apt update
    sudo apt install -y git curl jq whois nmap dnsutils python3 golang || warn "apt install partially failed"
  else
    warn "Non-APT system detected — please install dependencies manually or ensure Go is present."
  fi

  # Install go tools into $GOPATH/bin (defaults to $HOME/go/bin)
  if ! have go; then
    warn "Go not found — try: sudo apt install golang or install from https://go.dev"
  else
    declare -A GOT=( \
      [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" \
      [httpx]="github.com/projectdiscovery/httpx/cmd/httpx@latest" \
      [dnsx]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest" \
      [naabu]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest" \
      [katana]="github.com/projectdiscovery/katana/cmd/katana@latest" \
      [gowitness]="github.com/sensepost/gowitness@latest" \
      [waybackurls]="github.com/tomnomnom/waybackurls@latest" \
      [anew]="github.com/tomnomnom/anew@latest" )
    for t in "${!GOT[@]}"; do
      if ! have "$t"; then
        info "Installing $t via go (may take a while)..."
        GO111MODULE=on go install -v "${GOT[$t]}" || warn "go install $t failed"
      fi
    done
    export PATH="$PATH:$HOME/go/bin"
  fi
  ok "Auto-install complete. Ensure $HOME/go/bin is in PATH."
}

check_deps() {
  local missing=()
  for t in "${REQUIRED[@]}"; do have "$t" || missing+=("$t"); done
  if ((${#missing[@]})); then
    warn "Missing required tools: ${missing[*]}"
    echo -en "${YELLOW}Attempt auto-install of missing tools? [y/N]: ${RESET}"
    read -r ans || true
    if [[ "${ans:-N}" =~ ^[Yy]$ ]]; then
      auto_install_all
    else
      err "Please install the tools listed and re-run: ${missing[*]}"
      exit 1
    fi
  fi
}

# ----------------------------- Helper functions -----------------------------
subdomains_file() { echo "${WORKDIR}/${input_domain}.subdomains.txt"; }
resolved_file()   { echo "${WORKDIR}/${input_domain}.resolved.txt"; }
live_file()       { echo "${WORKDIR}/${input_domain}.live.txt"; }
endpoints_file()  { echo "${WORKDIR}/${input_domain}.endpoints.txt"; }
secrets_file()    { echo "${WORKDIR}/${input_domain}.secrets.txt"; }
ips_file()        { echo "${WORKDIR}/${input_domain}.ips.txt"; }
whois_file()      { echo "${WORKDIR}/reports/${input_domain}.whois.txt"; }
dns_file()        { echo "${WORKDIR}/reports/${input_domain}.dns.txt"; }
ports_file()      { echo "${WORKDIR}/${input_domain}.ports.txt"; }

# Check httpx accepts -l (list) flag. Falls back to stdin if not.
httpx_supports_list() {
  if httpx -h 2>&1 | grep -q -- '--list'; then
    return 0
  fi
  if httpx -h 2>&1 | grep -q -- '-l'; then
    return 0
  fi
  return 1
}

# ----------------------------- Core functions --------------------------------

prompt_domain() {
  if [[ -z "${input_domain}" ]]; then
    echo -en "${BOLD}Enter target domain (example.com): ${RESET}"
    read -r input_domain
    [[ -n "$input_domain" ]] || { err "No domain provided"; exit 1; }
  fi
}

run_subfinder() {
  prompt_domain; hr
  info "Running subdomain enumeration (subfinder)..."
  # Use safer subset of sources if subfinder is unstable
  if have subfinder; then
    # Avoiding known unstable sources is left to subfinder config; use default and catch failures
    if ! subfinder -d "$input_domain" -all -silent | sort -u | tee "$(subdomains_file)"; then
      warn "subfinder crashed — trying a more conservative run"
      subfinder -d "$input_domain" -silent | sort -u | tee "$(subdomains_file)" || err "subfinder run failed"
    fi
    ok "Subdomains saved: $(subdomains_file)"
  else
    err "subfinder not found"
  fi
}

resolve_subdomains() {
  prompt_domain; hr
  info "Resolving subdomains (dnsx)..."
  if ! have dnsx; then err "dnsx not found"; return 1; fi
  if [[ ! -s "$(subdomains_file)" ]]; then warn "No subdomains list found; run option 1 first"; return 1; fi
  dnsx -l "$(subdomains_file)" -silent -a | tee "$(resolved_file)" || true
  # extract IPs (support lines like domain [ip1,ip2])
  awk '{for(i=1;i<=NF;i++) if ($i ~ /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/) print $i}' "$(resolved_file)" \
    | tr -d '[], ' | sort -u > "$(ips_file)" || true
  if [[ -s "$(ips_file)" ]]; then
    ok "Resolved IPs saved: $(ips_file)"
  else
    warn "No IPs extracted from resolved output"
  fi
}

check_live_http() {
  prompt_domain; hr
  info "Checking for live HTTP(s) servers (httpx)..."

  if [[ ! -s "$(subdomains_file)" ]]; then
    err "No subdomains found — run subdomain enumeration first."
    return 1
  fi

  # Choose httpx invocation based on installed version
  if httpx_supports_list; then
    httpx -l "$(subdomains_file)" -title -status-code -tech-detect -web-server -follow-redirects \
      -timeout 6 -threads 50 -mc 200,201,202,204,301,302,307,308,401,403 -silent | tee "$(live_file)"
  else
    # older httpx reads from stdin
    cat "$(subdomains_file)" | httpx -title -status-code -tech-detect -web-server -follow-redirects \
      -timeout 6 -threads 50 -mc 200,201,202,204,301,302,307,308,401,403 -silent | tee "$(live_file)"
  fi

  if [[ -s "$(live_file)" ]]; then
    ok "Live hosts saved: $(live_file)"
    info "Sample (first 20):"
    head -n 20 "$(live_file)" | sed 's/^/  • /'
  else
    warn "No live hosts detected."
  fi
}

screenshot_hosts() {
  prompt_domain; hr
  info "Taking screenshots of live hosts (gowitness/eyewitness if available)..."
  if [[ ! -s "$(live_file)" ]]; then warn "Live hosts missing — run live check first"; return 1; fi
  cut -d ' ' -f1 "$(live_file)" > "${WORKDIR}/_urls.txt"
  if have gowitness; then
    gowitness file -f "${WORKDIR}/_urls.txt" -P "${WORKDIR}/shots" --timeout 15 || warn "gowitness error"
  elif have eyewitness; then
    eyewitness --web --threads 5 -f "${WORKDIR}/_urls.txt" -d "${WORKDIR}/shots" || warn "eyewitness error"
  else
    warn "No screenshot tool available; install gowitness or eyewitness"
  fi
  ok "Screenshots (if any) saved under ${WORKDIR}/shots"
}

collect_endpoints_and_secrets() {
  prompt_domain; hr
  info "Collecting endpoints (wayback/katana) and scanning for secrets..."

  if [[ ! -s "$(live_file)" ]]; then warn "No live hosts; run option 2 first"; return 1; fi
  cut -d ' ' -f1 "$(live_file)" > "${WORKDIR}/_urls.txt"
  : > "$(endpoints_file)"
  if have katana; then
    katana -list "${WORKDIR}/_urls.txt" -silent -em js,json,txt | sort -u | tee -a "$(endpoints_file)" || true
  fi
  if have waybackurls; then
    cat "${WORKDIR}/_urls.txt" | waybackurls | sort -u | tee -a "$(endpoints_file)" || true
  fi
  sort -u "$(endpoints_file)" -o "$(endpoints_file)" 2>/dev/null || true
  ok "Endpoints saved: $(endpoints_file)"

  # Simple, safe secret regexes (double-quoted to avoid quote issues)
  declare -a re_patterns=(
    "AKIA[0-9A-Z]{16}"
    "AIza[0-9A-Za-z_-]{35}"
    "sk_live_[0-9a-zA-Z]{24,}"
    "xox[baprs]-[0-9A-Za-z-]+"
    "facebook[[:space:][:alnum:][:punct:]]{0,100}[\"'][0-9a-f]{32}[\"']"
    "secret[_-]?key[\"'[:space:]:=]+[0-9A-Za-z-_/]{12,}"
    "api[_-]?key[\"'[:space:]:=]+[0-9A-Za-z-_/]{12,}"
  )

  : > "$(secrets_file)"
  if [[ -s "$(endpoints_file)" ]]; then
    while read -r url; do
      body=$(curl -m 8 -L -s "$url" 2>/dev/null | sed -n '1,400p' || true)
      for p in "${re_patterns[@]}"; do
        if [[ -n "$body" && "$body" =~ $p ]]; then
          printf "[HIT] %s :: %s\n" "$url" "${BASH_REMATCH[0]}" | tee -a "$(secrets_file)"
        fi
      done
    done < "$(endpoints_file)"
  fi
  ok "Secret scan complete. Results: $(secrets_file)"
}

fast_port_scan() {
  prompt_domain; hr
  info "Running fast TCP scan (naabu)..."
  if [[ ! -s "$(ips_file)" ]]; then
    resolve_subdomains || true
  fi
  if [[ ! -s "$(ips_file)" ]]; then warn "No IPs to scan"; return 1; fi
  naabu -list "$(ips_file)" -top-ports 1000 -silent | tee "$(ports_file)" || warn "naabu returned error"
  ok "Open ports saved: $(ports_file)"
  if have nmap; then
    echo -en "${YELLOW}Run targeted nmap service scans on found hosts? [y/N]: ${RESET}"
    read -r ans || true
    if [[ "${ans:-N}" =~ ^[Yy]$ && -s "$(ports_file)" ]]; then
      awk -F: '{print $1}' "$(ports_file)" | sort -u > "${WORKDIR}/_scan_hosts.txt"
      while read -r host; do
        ports=$(grep "^${host}:" "$(ports_file)" | awk -F: '{print $2}' | paste -sd, -)
        [[ -n "$ports" ]] && nmap -sV -Pn -p "$ports" "$host" -oN "${WORKDIR}/reports/${host}.nmap.txt" || true
      done < "${WORKDIR}/_scan_hosts.txt"
      ok "Nmap reports saved: ${WORKDIR}/reports"
    fi
  fi
}

whois_dns_report() {
  prompt_domain; hr
  info "Collecting WHOIS and DNS records..."
  whois "$input_domain" > "$(whois_file)" 2>/dev/null || true
  {
    echo "=== A ==="; dig +short A "$input_domain"
    echo "=== AAAA ==="; dig +short AAAA "$input_domain"
    echo "=== NS ==="; dig +short NS "$input_domain"
    echo "=== MX ==="; dig +short MX "$input_domain"
    echo "=== TXT ==="; dig +short TXT "$input_domain"
    echo "=== CNAME ==="; dig +short CNAME "$input_domain"
  } | tee "$(dns_file)"
  ok "WHOIS & DNS saved: $(whois_file) and $(dns_file)"
}

pipeline_all() {
  prompt_domain
  run_subfinder
  resolve_subdomains
  check_live_http
  screenshot_hosts
  collect_endpoints_and_secrets
  fast_port_scan
  whois_dns_report
  ok "Full pipeline complete. Workspace: ${WORKDIR}"
}

# ----------------------------- Menu ----------------------------------------
menu() {
  hr
  echo -e "${BOLD}${CYAN}====================[ DomainHunter Menu ]====================${RESET}"
  echo -e "${YELLOW}[1] Subdomain Enumeration${RESET}"
  echo -e "${YELLOW}[2] Live HTTP Probing${RESET}"
  echo -e "${YELLOW}[3] Screenshots${RESET}"
  echo -e "${YELLOW}[4] Endpoints + Secret Scan${RESET}"
  echo -e "${YELLOW}[5] Fast Port Scan${RESET}"
  echo -e "${YELLOW}[6] WHOIS & DNS${RESET}"
  echo -e "${YELLOW}[7] Full Pipeline (1→6)${RESET}"
  echo -e "${YELLOW}[8] Set / Change Target Domain${RESET}"
  echo -e "${YELLOW}[9] Install Missing Dependencies${RESET}"
  echo -e "${YELLOW}[0] Exit${RESET}"
  hr
}

set_domain_interactive() { input_domain=""; prompt_domain; ok "Target set: ${input_domain}"; }

# ----------------------------- Main ----------------------------------------
check_deps
while true; do
  menu
  [[ -n "$input_domain" ]] && echo -e "${BOLD}Current target:${RESET} ${input_domain}"
  echo -en "${BOLD}Choose option: ${RESET}"; read -r choice || true
  case "${choice:-}" in
    1) run_subfinder ;;
    2) check_live_http ;;
    3) screenshot_hosts ;;
    4) collect_endpoints_and_secrets ;;
    5) fast_port_scan ;;
    6) whois_dns_report ;;
    7) pipeline_all ;;
    8) set_domain_interactive ;;
    9) auto_install_all ;;
    0) ok "Goodbye"; exit 0 ;;
    *) warn "Invalid choice" ;;
  esac
done
