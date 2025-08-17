#!/usr/bin/env bash
# ============================================================================
# DomainHunter 3.0 – Robust Subdomain & Recon Tool (Kali + Termux friendly)
# Author: Lucky (Cyber Ghost)  |  Made by HackOps Academy
# License: MIT
# ============================================================================
# Highlights:
# - Hardened deps detection + one-key installer (Option 9)
# - Handles OLD/WRONG httpx binaries (Python "httpx" name collision) gracefully
# - Safe subfinder mode to avoid known crashes; fallback sources available
# - dnsx parsing hardened; dig fallback; IP extraction fixed
# - httpx compatibility layer (supports: new -l/-t OR stdin-only/threads flag missing)
# - Clear logs, colored TUI, well-ordered workspace outputs
# ============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

# ----------------------------- UI -------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'
hr()  { printf "${CYAN}%*s${RESET}\n" "$(tput cols 2>/dev/null || echo 80)" | tr ' ' '─'; }
info(){ echo -e "${CYAN}[i]${RESET} $*"; }
ok()  { echo -e "${GREEN}[✔]${RESET} $*"; }
warn(){ echo -e "${YELLOW}[!]${RESET} $*"; }
err() { echo -e "${RED}[✘]${RESET} $*"; }

cleanup(){ trap - EXIT INT; }
trap cleanup EXIT INT

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

# ----------------------------- Workspace ------------------------------------
DATE_TAG="$(date +%Y%m%d-%H%M%S)"
WORKDIR="DomainHunter-${DATE_TAG}"
LOGFILE="${WORKDIR}/domainhunter.log"
mkdir -p "$WORKDIR"/{shots,reports}
: > "$LOGFILE"
exec > >(tee -a "$LOGFILE") 2>&1

input_domain=""

# ----------------------------- Deps -----------------------------------------
# Required CLI
REQUIRED=(subfinder dnsx httpx naabu whois dig jq)
OPTIONAL=(amass assetfinder gowitness eyewitness katana waybackurls nmap anew)

have(){ command -v "$1" >/dev/null 2>&1; }

# Detect if installed httpx is the ProjectDiscovery one (not Python httpx CLI).
is_pd_httpx(){
  if ! have httpx; then return 1; fi
  # PD build prints version banner containing projectdiscovery or has flags like -status-code
  if httpx -version 2>/dev/null | grep -qi 'projectdiscovery'; then return 0; fi
  if httpx -h 2>&1 | grep -q '\-status-code'; then return 0; fi
  return 1
}

# Choose a working httpx binary if system "httpx" is wrong
pick_httpx(){
  if is_pd_httpx; then echo "httpx"; return 0; fi
  # Try Go bin explicitly
  local gohttpx="$HOME/go/bin/httpx"
  if [[ -x "$gohttpx" ]]; then
    if "$gohttpx" -h 2>&1 | grep -q '\-status-code'; then
      echo "$gohttpx"; return 0
    fi
  fi
  # As a last resort, return "httpx" and the caller will warn
  echo "httpx"
}

# Does httpx support -l (list file)?
httpx_supports_list(){
  local hx="$1"
  "$hx" -h 2>&1 | grep -Eq '(^| )[~-]l(,| |$)|--list'
}

# Does httpx support -t or --threads?
httpx_supports_threads(){
  local hx="$1"
  "$hx" -h 2>&1 | grep -Eq '(^| )[~-]t(,| |$)|--threads'
}

auto_install_all(){
  info "Installing/Updating dependencies (Kali/Termux best-effort)…"
  if have apt; then
    sudo apt update || true
    sudo apt install -y git curl jq whois nmap dnsutils python3 golang || true
  elif have pkg; then
    pkg update || true
    pkg install -y git curl jq whois dnsutils nmap golang python || true
  else
    warn "No apt/pkg found. Please install dependencies manually for your OS."
  fi

  if have go; then
    export PATH="$PATH:$(go env GOPATH 2>/dev/null || echo "$HOME/go")/bin"
    declare -A GOT=(
      [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
      [dnsx]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
      [httpx]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
      [naabu]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
      [katana]="github.com/projectdiscovery/katana/cmd/katana@latest"
      [gowitness]="github.com/sensepost/gowitness@latest"
      [waybackurls]="github.com/tomnomnom/waybackurls@latest"
      [anew]="github.com/tomnomnom/anew@latest"
    )
    for t in "${!GOT[@]}"; do
      if ! have "$t"; then info "Installing $t via Go…"; GO111MODULE=on go install -v "${GOT[$t]}" || warn "Failed: $t"; fi
    done
  else
    warn "Go toolchain not found; install golang to get latest PD tools."
  fi
  ok "Dependency install/update completed."
}

check_deps(){
  local missing=()
  for t in "${REQUIRED[@]}"; do have "$t" || missing+=("$t"); done
  if ((${#missing[@]})); then
    warn "Missing required tools: ${missing[*]}"
    echo -en "${YELLOW}Run auto-installer now? [y/N]: ${RESET}"
    read -r a || true
    if [[ "${a:-N}" =~ ^[Yy]$ ]]; then
      auto_install_all
    else
      err "Install missing tools and re-run."
      exit 1
    fi
  fi
}

# ----------------------------- File helpers ---------------------------------
subdomains_file(){ echo "${WORKDIR}/${input_domain}.subdomains.txt"; }
resolved_file(){   echo "${WORKDIR}/${input_domain}.resolved.txt"; }
live_file(){       echo "${WORKDIR}/${input_domain}.live.txt"; }
endpoints_file(){  echo "${WORKDIR}/${input_domain}.endpoints.txt"; }
secrets_file(){    echo "${WORKDIR}/${input_domain}.secrets.txt"; }
ips_file(){        echo "${WORKDIR}/${input_domain}.ips.txt"; }
whois_file(){      echo "${WORKDIR}/reports/${input_domain}.whois.txt"; }
dns_file(){        echo "${WORKDIR}/reports/${input_domain}.dns.txt"; }
ports_file(){      echo "${WORKDIR}/${input_domain}.ports.txt"; }

# ----------------------------- Core -----------------------------------------
prompt_domain(){
  if [[ -z "${input_domain}" ]]; then
    echo -en "${BOLD}Enter target domain (example.com): ${RESET}"
    read -r input_domain
    [[ -n "$input_domain" ]] || { err "No domain provided"; exit 1; }
  fi
}

run_subfinder(){
  prompt_domain; hr
  info "Running subdomain enumeration (subfinder)…"
  # Safe run first; if it errors, fallback to conservative sources
  if subfinder -d "$input_domain" -all -silent -timeout 12 -max-time 3m 2>/dev/null | sort -u | tee "$(subdomains_file)"; then
    :
  else
    warn "subfinder had issues, retrying with conservative sources…"
    subfinder -d "$input_domain" -sources alienvault,crtsh,waybackarchive,hackertarget -silent -timeout 12 -max-time 2m \
      | sort -u | tee "$(subdomains_file)" || true
  fi

  if [[ -s "$(subdomains_file)" ]]; then
    ok "Subdomains saved: $(subdomains_file)"
  else
    err "No subdomains found."
  fi
}

resolve_subdomains(){
  prompt_domain; hr
  info "Resolving subdomains (dnsx)…"
  if [[ ! -s "$(subdomains_file)" ]]; then warn "No subdomains list; run option 1 first."; return 1; fi

  # Prefer dnsx (fast). Use -resp to keep host mapping.
  if dnsx -l "$(subdomains_file)" -a -resp -silent 2>/dev/null | tee "$(resolved_file)"; then
    :
  else
    warn "dnsx failed, falling back to dig (slower)…"
    : > "$(resolved_file)"
    while read -r h; do
      ips=$(dig +short A "$h" | sed '/[^0-9.]/d' || true)
      if [[ -n "$ips" ]]; then echo "$h $ips" >>"$(resolved_file)"; fi
    done <"$(subdomains_file)"
  fi

  # Extract unique IPv4s
  grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' "$(resolved_file)" | sort -u >"$(ips_file)" || true

  if [[ -s "$(ips_file)" ]]; then
    ok "Resolved IPs saved: $(ips_file)"
  else
    warn "No IPs extracted from resolution output."
  fi
}

check_live_http(){
  prompt_domain; hr
  info "Probing live HTTP(S) (httpx)…"

  if [[ ! -s "$(subdomains_file)" ]]; then err "No subdomains file. Run option 1 first."; return 1; fi

  local HX; HX="$(pick_httpx)"
  if ! is_pd_httpx && [[ "$HX" == "httpx" ]]; then
    err "Your 'httpx' is NOT ProjectDiscovery's binary. Please install PD httpx:"
    echo "  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    return 1
  fi

  if httpx_supports_list "$HX"; then
    # Newer PD httpx supports -l
    if httpx_supports_threads "$HX"; then
      "$HX" -l "$(subdomains_file)" -title -status-code -tech-detect -web-server -follow-redirects \
        -timeout 6 -t 50 -mc 200,201,202,204,301,302,307,308,401,403 -silent | tee "$(live_file)"
    else
      "$HX" -l "$(subdomains_file)" -title -status-code -tech-detect -web-server -follow-redirects \
        -timeout 6 -mc 200,201,202,204,301,302,307,308,401,403 -silent | tee "$(live_file)"
    fi
  else
    # Older PD httpx only reads from stdin
    if httpx_supports_threads "$HX"; then
      cat "$(subdomains_file)" | "$HX" -title -status-code -tech-detect -web-server -follow-redirects \
        -timeout 6 -t 50 -mc 200,201,202,204,301,302,307,308,401,403 -silent | tee "$(live_file)"
    else
      cat "$(subdomains_file)" | "$HX" -title -status-code -tech-detect -web-server -follow-redirects \
        -timeout 6 -mc 200,201,202,204,301,302,307,308,401,403 -silent | tee "$(live_file)"
    fi
  fi

  if [[ -s "$(live_file)" ]]; then
    ok "Live hosts saved: $(live_file)"
    info "Sample (first 15):"; head -n 15 "$(live_file)" | sed 's/^/  • /'
  else
    warn "No live hosts detected."
  fi
}

screenshot_hosts(){
  prompt_domain; hr
  info "Taking screenshots (gowitness/eyewitness)…"
  if [[ ! -s "$(live_file)" ]]; then warn "No live hosts; run option 2 first."; return 1; fi
  cut -d ' ' -f1 "$(live_file)" > "${WORKDIR}/_urls.txt"
  if have gowitness; then
    gowitness file -f "${WORKDIR}/_urls.txt" -P "${WORKDIR}/shots" --timeout 15 || warn "gowitness error"
  elif have eyewitness; then
    eyewitness --web --threads 5 -f "${WORKDIR}/_urls.txt" -d "${WORKDIR}/shots" || warn "eyewitness error"
  else
    warn "No screenshot tool installed (gowitness/eyewitness)."
  fi
  ok "Screenshots (if any) saved to ${WORKDIR}/shots"
}

collect_endpoints_and_secrets(){
  prompt_domain; hr
  info "Collecting endpoints (katana/waybackurls) + secret scan…"
  if [[ ! -s "$(live_file)" ]]; then warn "No live hosts; run option 2 first."; return 1; fi

  cut -d ' ' -f1 "$(live_file)" > "${WORKDIR}/_urls.txt"
  : >"$(endpoints_file)"

  if have katana; then
    katana -list "${WORKDIR}/_urls.txt" -silent -em js,json,txt -aff -jc -fx \
      | sort -u | tee -a "$(endpoints_file)" || true
  fi
  if have waybackurls; then
    cat "${WORKDIR}/_urls.txt" | waybackurls | sort -u | tee -a "$(endpoints_file)" || true
  fi
  sort -u "$(endpoints_file)" -o "$(endpoints_file)" 2>/dev/null || true

  ok "Endpoints saved: $(endpoints_file)"

  # Lightweight secret patterns (quoted, POSIX classes)
  declare -a RE=(
    "AKIA[0-9A-Z]{16}"
    "AIza[0-9A-Za-z_-]{35}"
    "sk_live_[0-9a-zA-Z]{24,}"
    "xox[baprs]-[0-9A-Za-z-]+"
    "facebook[[:space:][:alnum:][:punct:]]{0,120}[\"'][0-9a-f]{32}[\"']"
    "secret[_-]?key[\"'[:space:]:=]+[0-9A-Za-z-_/]{12,}"
    "api[_-]?key[\"'[:space:]:=]+[0-9A-Za-z-_/]{12,}"
  )

  : >"$(secrets_file)"
  if [[ -s "$(endpoints_file)" ]]; then
    while read -r url; do
      body=$(curl -m 8 -L -s "$url" 2>/dev/null | sed -n '1,400p' || true)
      for pat in "${RE[@]}"; do
        if [[ -n "$body" && "$body" =~ $pat ]]; then
          printf "[HIT] %s :: %s\n" "$url" "${BASH_REMATCH[0]}" | tee -a "$(secrets_file)"
        fi
      done
    done <"$(endpoints_file)"
  fi
  ok "Secret scan complete. Results: $(secrets_file)"
}

fast_port_scan(){
  prompt_domain; hr
  info "Fast TCP scan (naabu)…"
  [[ -s "$(ips_file)" ]] || resolve_subdomains || true
  if [[ ! -s "$(ips_file)" ]]; then warn "No IPs found; skipping naabu."; return 1; fi

  naabu -list "$(ips_file)" -top-ports 1000 -silent | tee "$(ports_file)" || warn "naabu encountered issues"
  ok "Open ports saved: $(ports_file)"

  if have nmap; then
    echo -en "${YELLOW}Run targeted nmap -sV on discovered ports? [y/N]: ${RESET}"
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

whois_dns_report(){
  prompt_domain; hr
  info "WHOIS & DNS records…"
  whois "$input_domain" >"$(whois_file)" 2>/dev/null || true
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

pipeline_all(){
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
menu(){
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
  echo -e "${YELLOW}[9] Install / Update Dependencies${RESET}"
  echo -e "${YELLOW}[0] Exit${RESET}"
  hr
}

set_domain_interactive(){ input_domain=""; prompt_domain; ok "Target set: ${input_domain}"; }

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
    4) collect_endpoints_and_secrets;;
    5) fast_port_scan;;
    6) whois_dns_report;;
    7) pipeline_all;;
    8) set_domain_interactive;;
    9) auto_install_all;;
    0) ok "Goodbye!"; exit 0;;
    *) warn "Invalid choice.";;
  esac
done
