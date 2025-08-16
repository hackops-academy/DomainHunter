#!/usr/bin/env bash
# ============================================================================
# DomainHunter - Advanced Subdomain & Recon Tool (Kali Linux & Termux)
# Author: Lucky (Cyber Ghost)
# Repo  : https://github.com/yourusername/DomainHunter
# License: MIT
# ============================================================================
# Features
#   1) Subdomain enumeration (subfinder + optional amass/assetfinder)
#   2) DNS resolution (dnsx) & live host discovery (httpx)
#   3) Screenshots of live hosts (gowitness; fall back to eyewitness if present)
#   4) Endpoints & JS discovery (katana/waybackurls) + secrets regex scan
#   5) Fast port scan (naabu) + optional nmap service probe
#   6) WHOIS & DNS records report
#   7) Full pipeline mode (run everything end-to-end)
#   8) Pretty TUI menu, logging, timestamped workspace, graceful error handling
# ============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

# ----------------------------- Colors & UI ----------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
RESET='\033[0m'

hr() { printf "${CYAN}%*s${RESET}\n" "$(tput cols)" | tr ' ' '─'; }
info() { echo -e "${CYAN}[i]${RESET} $*"; }
ok()   { echo -e "${GREEN}[✔]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
err()  { echo -e "${RED}[✘]${RESET} $*"; }

cleanup() {
  trap - EXIT INT
}
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

# ----------------------------- Globals --------------------------------------
PLATFORM="$(uname -o 2>/dev/null || uname -s)"
DATE_TAG="$(date +%Y%m%d-%H%M%S)"
WORKDIR="DomainHunter-${DATE_TAG}"
LOGFILE="${WORKDIR}/domainhunter.log"
mkdir -p "$WORKDIR"{,/shots,/reports}
touch "$LOGFILE"

# Save command outputs to log as well
exec > >(tee -a "$LOGFILE") 2>&1

# ----------------------------- Dependencies ---------------------------------
# Core tools (prefer Go versions for speed). We'll try to detect and optionally help install.
REQUIRED=(
  subfinder
  dnsx
  httpx
  naabu
  whois
  dig
  jq
)
# Nice-to-have
OPTIONAL=(
  amass
  assetfinder
  gowitness
  eyewitness
  katana
  waybackurls
  nmap
  anew
)

have() { command -v "$1" >/dev/null 2>&1; }

check_deps() {
  local missing=()
  for t in "${REQUIRED[@]}"; do have "$t" || missing+=("$t"); done
  if ((${#missing[@]})); then
    warn "Missing required tools: ${missing[*]}"
    echo -en "${YELLOW}Attempt lightweight auto-install? [y/N]: ${RESET}"
    read -r ans || true
    if [[ "${ans:-N}" =~ ^[Yy]$ ]]; then
      auto_install "${missing[@]}"
    else
      err "Please install required tools and re-run."
      cat <<'HINT'

Kali (apt):
  sudo apt update && sudo apt install -y subfinder httpx-toolkit dnsx naabu whois dnsutils jq nmap
Go (latest):
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
  go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
  go install -v github.com/projectdiscovery/katana/cmd/katana@latest
  go install -v github.com/sensepost/gowitness@latest
  go install -v github.com/tomnomnom/waybackurls@latest
  go install -v github.com/tomnomnom/anew@latest
Termux (pkg):
  pkg update && pkg install -y golang python whois dnsutils jq nmap git
  # then use the `go install` lines above (ensure $GOPATH/bin in PATH)
HINT
      exit 1
    fi
  fi
}

auto_install() {
  # Best-effort installer covering Kali apt/pkg and Go installs when possible.
  local to_install=("$@")
  if have apt; then sudo apt update || true; fi
  for t in "${to_install[@]}"; do
    if have "$t"; then continue; fi
    case "$t" in
      subfinder|httpx|dnsx|naabu)
        if have apt; then sudo apt install -y "${t}" || true; fi
        ;;
      whois)
        if have apt; then sudo apt install -y whois || true; fi
        ;;
      dig)
        if have apt; then sudo apt install -y dnsutils || true; fi
        ;;
      jq)
        if have apt; then sudo apt install -y jq || true; fi
        ;;
      *) ;;
    esac
    have "$t" || warn "${t} not installed via apt. If Go is available, attempting go install…"
    if have go; then
      case "$t" in
        subfinder)   go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest;;
        httpx)       go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest;;
        dnsx)        go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest;;
        naabu)       go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest;;
        katana)      go install -v github.com/projectdiscovery/katana/cmd/katana@latest;;
        gowitness)   go install -v github.com/sensepost/gowitness@latest;;
        waybackurls) go install -v github.com/tomnomnom/waybackurls@latest;;
        anew)        go install -v github.com/tomnomnom/anew@latest;;
        *) ;;
      esac
    fi
  done
}

# ----------------------------- Helpers --------------------------------------
input_domain=""

prompt_domain() {
  if [[ -z "${input_domain}" ]]; then
    echo -en "${BOLD}Enter target domain (e.g., example.com): ${RESET}"
    read -r input_domain
    [[ -n "${input_domain}" ]] || { err "No domain provided"; exit 1; }
  fi
}

# Files per run
subdomains_file() { echo "${WORKDIR}/${input_domain}.subdomains.txt"; }
resolved_file()   { echo "${WORKDIR}/${input_domain}.resolved.txt"; }
live_file()       { echo "${WORKDIR}/${input_domain}.live.txt"; }
endpoints_file()  { echo "${WORKDIR}/${input_domain}.endpoints.txt"; }
secrets_file()    { echo "${WORKDIR}/${input_domain}.secrets.txt"; }
ips_file()        { echo "${WORKDIR}/${input_domain}.ips.txt"; }
whois_file()      { echo "${WORKDIR}/reports/${input_domain}.whois.txt"; }
dns_file()        { echo "${WORKDIR}/reports/${input_domain}.dns.txt"; }
ports_file()      { echo "${WORKDIR}/${input_domain}.ports.txt"; }

# ----------------------------- Core Actions ---------------------------------
run_subfinder() {
  prompt_domain
  hr; info "Subdomain enumeration with subfinder (passive + recursive)"
  subfinder -d "$input_domain" -all -recursive -silent \
    | sort -u | tee "$(subdomains_file)"
  ok "Saved: $(subdomains_file)"
}

resolve_subdomains() {
  prompt_domain
  hr; info "Resolving subdomains -> A records with dnsx"
  dnsx -silent -a -resp-only -l "$(subdomains_file)" \
    | tee "$(resolved_file)"
  ok "Saved: $(resolved_file)"
  # Extract unique IPs
  awk '{print $2}' "$(resolved_file)" 2>/dev/null | sed 's/^[^ ]* //g' | sed 's/,/\n/g' | sed 's/\[\|\]//g' | sort -u > "$(ips_file)" || true
}

check_live_http() {
  prompt_domain
  hr; info "Probing live HTTP(s) with httpx"
  local input="$(subdomains_file)"
  if [[ ! -s "$input" ]]; then err "Missing subdomains list. Run option 1 first."; return 1; fi
  httpx -l "$input" -silent -status-code -title -tech-detect -mc 200,201,202,204,301,302,307,308,401,403 \
    | tee "$(live_file)"
  ok "Saved: $(live_file)"
}

screenshot_hosts() {
  prompt_domain
  hr; info "Taking screenshots of live hosts"
  local live="$(live_file)"
  if [[ ! -s "$live" ]]; then err "Missing live hosts. Run option 2 first."; return 1; fi
  cut -d ' ' -f1 "$live" > "${WORKDIR}/_urls.txt"
  if have gowitness; then
    gowitness file -f "${WORKDIR}/_urls.txt" -P "${WORKDIR}/shots" --timeout 15 --disable-logging || true
  elif have eyewitness; then
    eyewitness --web --threads 5 --timeout 15 --prepend-https -f "${WORKDIR}/_urls.txt" -d "${WORKDIR}/shots" || true
  else
    warn "No screenshot tool (gowitness/eyewitness) found. Skipping screenshots."
  fi
  ok "Screenshots (if any) saved under: ${WORKDIR}/shots"
}

collect_endpoints_and_secrets() {
  prompt_domain
  hr; info "Crawling for endpoints (katana/waybackurls) & scanning for secrets"
  local live="$(live_file)"
  if [[ ! -s "$live" ]]; then err "Missing live hosts. Run option 2 first."; return 1; fi
  : > "$(endpoints_file)"
  cut -d ' ' -f1 "$live" > "${WORKDIR}/_urls.txt"

  # Crawl endpoints
  if have katana; then
    katana -list "${WORKDIR}/_urls.txt" -silent -em js,json,txt -jc -aff -kf -fx \
      | sort -u | tee -a "$(endpoints_file)"
  fi
  if have waybackurls; then
    cat "${WORKDIR}/_urls.txt" | waybackurls | sort -u | tee -a "$(endpoints_file)"
  fi
  sort -u "$(endpoints_file)" -o "$(endpoints_file)"
  ok "Saved endpoints: $(endpoints_file)"

  # Secrets regex (safe array)
  hr; info "Scanning endpoints for potential secrets (regex-based)"
  : > "$(secrets_file)"
  declare -a re=(
    'AKIA[0-9A-Z]{16}'
    'AIza[0-9A-Za-z_-]{35}'
    'sk_live_[0-9a-zA-Z]{24,}'
    'xox[baprs]-[0-9A-Za-z-]+'
    'facebook[\s\S]*?[\'"][0-9a-f]{32}[\'"]'
    'secret[_-]?key["'\''\s:=]+[0-9A-Za-z\-_/.]{12,}'
    'api[_-]?key["'\''\s:=]+[0-9A-Za-z\-_/.]{12,}'
  )

  if [[ -s "$(endpoints_file)" ]]; then
    while read -r url; do
      body=$(curl -m 10 -L -s "$url" | sed -n '1,400p' || true)
      for r in "${re[@]}"; do
        if [[ -n "$body" && "$body" =~ $r ]]; then
          printf "[HIT] %s :: %s\n" "$url" "${BASH_REMATCH[0]}" | tee -a "$(secrets_file)"
        fi
      done
    done < "$(endpoints_file)"
  fi
  ok "Secret scan complete. Potential matches: $(secrets_file)"
}


fast_port_scan() {
  prompt_domain
  hr
  info "Fast TCP scan with naabu (top ports). Optional nmap service probe."

  # Prefer resolved IPs; if missing, resolve now
  if [[ ! -s "$(resolved_file)" ]]; then resolve_subdomains || true; fi

  if [[ -s "$(resolved_file)" ]]; then
    awk '{print $NF}' "$(resolved_file)" | tr ',' '\n' | sed 's/[\[\]]//g' | sort -u > "$(ips_file)"
  fi

  if [[ ! -s "$(ips_file)" ]]; then
    warn "No IPs from subdomain resolution; scanning the apex domain directly."
    echo "$input_domain" > "$(ips_file)"
  fi

  naabu -list "$(ips_file)" -top-ports 1000 -rate 1000 -silent | tee "$(ports_file)"
  ok "Saved open ports: $(ports_file)"

 if have nmap; then
  echo -en "${YELLOW}Run nmap service/version scan on open ports? [y/N]: ${RESET}"
  read -r ans || true
  if [[ "${ans:-N}" =~ ^[Yy]$ && -s "$(ports_file)" ]]; then
    awk -F: '{print $1}' "$(ports_file)" | sort -u > "${WORKDIR}/_scan_hosts.txt"
    while read -r host; do
      ports=$(grep "^${host}:" "$(ports_file)" | awk -F: '{print $2}' | paste -sd, -)
      [[ -n "$ports" ]] && nmap -sV -Pn -p "$ports" "$host" -oN "${WORKDIR}/reports/${host}.nmap.txt" || true
    done < "${WORKDIR}/_scan_hosts.txt"
    ok "Nmap reports saved under ${WORKDIR}/reports"
  fi
fi

}

  

whois_dns_report() {
  prompt_domain
  hr; info "WHOIS & DNS records"
  whois "$input_domain" > "$(whois_file)" 2>/dev/null || true
  {
    echo "=== A ===";     dig +short A     "$input_domain"
    echo "=== AAAA ===";  dig +short AAAA  "$input_domain"
    echo "=== NS ===";    dig +short NS    "$input_domain"
    echo "=== MX ===";    dig +short MX    "$input_domain"
    echo "=== TXT ===";   dig +short TXT   "$input_domain"
    echo "=== CNAME ==="; dig +short CNAME "$input_domain"
  } | tee "$(dns_file)"
  ok "Saved: $(whois_file) and $(dns_file)"
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
  ok "Pipeline complete. Workspace: ${WORKDIR}"
}

# ----------------------------- Menu -----------------------------------------
menu() {
  hr
  echo -e "${BOLD}${CYAN}====================[ DomainHunter Menu ]====================${RESET}"
  echo -e "${YELLOW}[1] Subdomain Enumeration${RESET}"
  echo -e "${YELLOW}[2] Live HTTP Probing (httpx)${RESET}"
  echo -e "${YELLOW}[3] Screenshots (gowitness/eyewitness)${RESET}"
  echo -e "${YELLOW}[4] Endpoints + Secrets Scan (katana/waybackurls)${RESET}"
  echo -e "${YELLOW}[5] Fast Port Scan (naabu + optional nmap)${RESET}"
  echo -e "${YELLOW}[6] WHOIS & DNS Report${RESET}"
  echo -e "${YELLOW}[7] 🔁 Full Pipeline (1→6)${RESET}"
  echo -e "${YELLOW}[8] Set/Change Target Domain${RESET}"
  echo -e "${YELLOW}[9] Exit${RESET}"
  echo -e "${BOLD}${CYAN}============================================================${RESET}"
}

set_domain_interactive() {
  input_domain=""
  prompt_domain
  ok "Target set to: ${input_domain}"
}

# ----------------------------- Main -----------------------------------------
check_deps

while true; do
  menu
  if [[ -n "$input_domain" ]]; then echo -e "${BOLD}Current target:${RESET} ${input_domain}"; fi
  echo -en "${BOLD}Choose an option: ${RESET}"; read -r choice || true
  case "${choice:-}" in
    1) run_subfinder;;
    2) check_live_http;;
    3) screenshot_hosts;;
    4) collect_endpoints_and_secrets;;
    5) fast_port_scan;;
    6) whois_dns_report;;
    7) pipeline_all;;
    8) set_domain_interactive;;
    9) ok "Goodbye"; exit 0;;
    *) warn "Invalid choice";;
  esac
 done
