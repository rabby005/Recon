#!/bin/bash
# ╔══════════════════════════════════════════════════════════════╗
# ║         full_scn — Unified Recon + XSS Scanner              ║
# ║       CSRRrecon (subdomain recon) + scn1 (XSS/sink)         ║
# ╚══════════════════════════════════════════════════════════════╝
#
#  Install:  bash full_scn.sh --install
#  Run:      bash full_scn.sh -d example.com
#  Both:     bash full_scn.sh --install -d example.com

set -euo pipefail
IFS=$'\n\t'

# ── Script location ──────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CSRRRECON_DIR="${SCRIPT_DIR}/CSRRrecon"
SCN1_DIR="${SCRIPT_DIR}/scn1"

# ── Colors ──────────────────────────────────────────────────────
R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m'
C='\033[0;36m' B='\033[1m'   X='\033[0m'
D='\033[0;90m'

_info()    { echo -e "${C}[*]${X} $*"; }
_ok()      { echo -e "${G}[✔]${X} $*"; }
_warn()    { echo -e "${Y}[!]${X} $*"; }
_err()     { echo -e "${R}[✘]${X} $*" >&2; }
_step()    { echo -e "\n${B}${C}━━━ $* ━━━${X}\n"; }
_dim()     { echo -e "${D}    $*${X}"; }

# ── Banner ──────────────────────────────────────────────────────
print_banner() {
echo -e "${B}${C}"
cat << 'EOF'
  ███████╗██╗   ██╗██╗     ██╗          ███████╗ ██████╗███╗   ██╗
  ██╔════╝██║   ██║██║     ██║          ██╔════╝██╔════╝████╗  ██║
  █████╗  ██║   ██║██║     ██║          ███████╗██║     ██╔██╗ ██║
  ██╔══╝  ██║   ██║██║     ██║          ╚════██║██║     ██║╚██╗██║
  ██║     ╚██████╔╝███████╗███████╗     ███████║╚██████╗██║ ╚████║
  ╚═╝      ╚═════╝ ╚══════╝╚══════╝     ╚══════╝ ╚═════╝╚═╝  ╚═══╝
EOF
echo -e "${X}${D}       CSRRrecon + scn1 | Subdomain Recon → XSS/Sink Scanner${X}"
echo -e "${D}  ───────────────────────────────────────────────────────────${X}\n"
}

# ── Usage ───────────────────────────────────────────────────────
usage() {
echo -e "${B}Usage:${X}"
echo -e "  bash full_scn.sh ${C}--install${X}                  # শুধু সব tools install করো"
echo -e "  bash full_scn.sh ${C}-d example.com${X}             # install skip করে শুধু scan"
echo -e "  bash full_scn.sh ${C}--install -d example.com${X}   # install করে তারপর scan"
echo ""
echo -e "${B}Options:${X}"
echo -e "  ${C}-d, --domain${X}        Target domain (required for scan)"
echo -e "  ${C}--install${X}           Install all dependencies"
echo -e "  ${C}--mode${X}              CSRRrecon mode: --subdomains | --recon | --web | --osint"
echo -e "                      (default: --subdomains)"
echo -e "  ${C}--use-browser${X}       Enable Playwright browser for XSS scan (recommended)"
echo -e "  ${C}--concurrency N${X}     scn1 parallel workers (default: 5)"
echo -e "  ${C}--timeout N${X}         Request timeout in seconds (default: 15)"
echo -e "  ${C}--cookies STR${X}       Cookies for authenticated scan, e.g. 'session=abc'"
echo -e "  ${C}--headers STR${X}       Custom headers, e.g. 'X-Header=value'"
echo -e "  ${C}--skip-recon${X}        Skip CSRRrecon, use existing URL list"
echo -e "  ${C}--urls-file${X}         Use a custom scn1urls.txt file (skips CSRRrecon)"
echo -e "  ${C}--skip-xss${X}          Skip scn1 XSS scan"
echo -e "  ${C}-h, --help${X}          Show this help"
echo ""
echo -e "${B}Examples:${X}"
echo -e "  bash full_scn.sh --install -d example.com --use-browser"
echo -e "  bash full_scn.sh -d example.com --mode --recon --use-browser"
echo -e "  bash full_scn.sh -d example.com --urls-file my_urls.txt --use-browser"
exit 0
}

# ── Defaults ────────────────────────────────────────────────────
DOMAIN=""
DO_INSTALL=false
DO_SCAN=false
CSRRRECON_MODE="--subdomains"
USE_BROWSER=false
CONCURRENCY=5
TIMEOUT=15
COOKIES=""
HEADERS=""
SKIP_RECON=false
SKIP_XSS=false
CUSTOM_URLS_FILE=""

# ── Argument Parsing ────────────────────────────────────────────
[[ $# -eq 0 ]] && print_banner && usage

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain)         DOMAIN="$2"; DO_SCAN=true; shift 2 ;;
    --install)           DO_INSTALL=true; shift ;;
    --mode)              CSRRRECON_MODE="$2"; shift 2 ;;
    --use-browser)       USE_BROWSER=true; shift ;;
    --concurrency)       CONCURRENCY="$2"; shift 2 ;;
    --timeout)           TIMEOUT="$2"; shift 2 ;;
    --cookies)           COOKIES="$2"; shift 2 ;;
    --headers)           HEADERS="$2"; shift 2 ;;
    --skip-recon)        SKIP_RECON=true; shift ;;
    --skip-xss)          SKIP_XSS=true; shift ;;
    --urls-file)         CUSTOM_URLS_FILE="$2"; SKIP_RECON=true; shift 2 ;;
    -h|--help)           print_banner; usage ;;
    *)                   _err "Unknown option: $1"; usage ;;
  esac
done

print_banner

# ════════════════════════════════════════════════════════════════
#  INSTALL
# ════════════════════════════════════════════════════════════════
do_install() {
  _step "Installing All Dependencies"

  SUDO=""
  if [[ $EUID -ne 0 ]]; then
    command -v sudo &>/dev/null && SUDO="sudo" || \
      _warn "Not root and no sudo found — some installs may fail"
  fi

  _info "Updating apt and installing system packages..."
  $SUDO apt-get update -qq
  $SUDO apt-get install -y -qq \
    python3 python3-pip python3-venv \
    git curl wget unzip build-essential gcc \
    cmake ruby whois libpcap-dev zip python3-dev pv \
    dnsutils libssl-dev libffi-dev libxml2-dev libxslt1-dev \
    zlib1g-dev nmap jq lynx xvfb libxml2-utils procps \
    bsdmainutils libimage-exiftool-perl \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
    libxkbcommon-x11-0 libxcomposite-dev libxdamage1 \
    libxrandr2 libgbm-dev libpangocairo-1.0-0 2>/dev/null || \
    _warn "Some apt packages may have failed — continuing"
  _ok "System packages done"

  if ! command -v go &>/dev/null; then
    _info "Installing Go..."
    GO_VER="1.22.4"
    GOARCH="amd64"
    [[ "$(uname -m)" == "aarch64" || "$(uname -m)" == "arm64" ]] && GOARCH="arm64"
    wget -q "https://go.dev/dl/go${GO_VER}.linux-${GOARCH}.tar.gz" -O /tmp/go.tar.gz
    $SUDO rm -rf /usr/local/go
    $SUDO tar -C /usr/local -xzf /tmp/go.tar.gz
    rm -f /tmp/go.tar.gz
    export PATH="$PATH:/usr/local/go/bin"
    grep -q '/usr/local/go/bin' ~/.bashrc 2>/dev/null || \
      echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    grep -q 'GOPATH' ~/.bashrc 2>/dev/null || \
      echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
    _ok "Go $(go version) installed"
  else
    _ok "Go already installed: $(go version | awk '{print $3}')"
  fi
  export PATH="$PATH:/usr/local/go/bin:$(go env GOPATH 2>/dev/null)/bin"

  _info "Running CSRRrecon install.sh (this may take a while)..."
  if [[ -f "${CSRRRECON_DIR}/install.sh" ]]; then
    pushd "$CSRRRECON_DIR" > /dev/null
    bash install.sh
    popd > /dev/null
    _ok "CSRRrecon tools installed"
  else
    _err "CSRRrecon/install.sh not found"; exit 1
  fi

  _info "Installing scn1 Python dependencies..."
  pip3 install -q -r "${SCN1_DIR}/requirements.txt" --break-system-packages 2>/dev/null || \
  pip3 install -q -r "${SCN1_DIR}/requirements.txt" || \
    _warn "Some pip packages may have failed"
  _ok "scn1 pip dependencies installed"

  _info "Installing Playwright Chromium browser..."
  python3 -m playwright install chromium 2>/dev/null && \
    _ok "Playwright Chromium installed" || \
    _warn "Playwright browser install failed — run: python3 -m playwright install"

  echo ""
  _ok "${B}All dependencies installed successfully!${X}"
  _dim "You can now run: bash full_scn.sh -d example.com --use-browser"
  echo ""
}

[[ "$DO_INSTALL" == true ]] && do_install

# ════════════════════════════════════════════════════════════════
#  SCAN
# ════════════════════════════════════════════════════════════════
[[ "$DO_SCAN" == false ]] && exit 0

[[ -z "$DOMAIN" && "$SKIP_RECON" == false ]] && \
  { _err "No domain specified. Use -d example.com"; exit 1; }

# ── Output paths ────────────────────────────────────────────────
RESULTS_DIR="${SCRIPT_DIR}/results/${DOMAIN:-custom}"
ALLLINK_FILE="${RESULTS_DIR}/AllLink.txt"
SCN1URLS_FILE="${RESULTS_DIR}/scn1urls.txt"
XSS_DIR="${RESULTS_DIR}/xss_reports"
mkdir -p "$RESULTS_DIR" "$XSS_DIR"

_step "Target: ${DOMAIN:-custom}"
_dim "Results dir: ${RESULTS_DIR}"

export PATH="$PATH:/usr/local/go/bin:${HOME}/Tools:${HOME}/go/bin:$(go env GOPATH 2>/dev/null)/bin"

# ────────────────────────────────────────────────────────────────
#  PHASE 1 — CSRRrecon Recon
# ────────────────────────────────────────────────────────────────
if [[ "$SKIP_RECON" == true ]]; then
  if [[ -n "$CUSTOM_URLS_FILE" ]]; then
    cp "$CUSTOM_URLS_FILE" "$SCN1URLS_FILE"
    COUNT=$(wc -l < "$SCN1URLS_FILE" | tr -d ' ')
    _ok "Using custom URLs file: ${COUNT} entries → scn1urls.txt"
  elif [[ -f "$SCN1URLS_FILE" ]]; then
    COUNT=$(wc -l < "$SCN1URLS_FILE" | tr -d ' ')
    _ok "Using existing scn1urls.txt: ${COUNT} entries"
  else
    _err "No URLs file found. Run without --skip-recon or provide --urls-file"
    exit 1
  fi
else
  _step "Phase 1 — Recon (CSRRrecon)"
  _info "Mode: ${CSRRRECON_MODE} | Domain: ${DOMAIN}"

  [[ ! -f "${CSRRRECON_DIR}/CSRRrecon.sh" ]] && \
    { _err "CSRRrecon.sh not found. Run --install first."; exit 1; }

  pushd "$CSRRRECON_DIR" > /dev/null
  bash CSRRrecon.sh -d "$DOMAIN" $CSRRRECON_MODE
  popd > /dev/null

  # ────────────────────────────────────────────────────────────
  #  PHASE 1.5 — AllLink.txt ও scn1urls.txt তৈরি
  # ────────────────────────────────────────────────────────────
  _step "Phase 1.5 — URL Collection → AllLink.txt & scn1urls.txt"

  RECON_BASE="${CSRRRECON_DIR}/Recon/${DOMAIN}"

  # CSRRrecon থেকে সব relevant URL source files
  URL_SOURCES=(
    "${RECON_BASE}/subdomains/subdomains.txt"
    "${RECON_BASE}/webs/webs_all.txt"
    "${RECON_BASE}/webs/webs.txt"
    "${RECON_BASE}/webs/webs_uncommon_ports.txt"
    "${RECON_BASE}/webs/url_extract.txt"
    "${RECON_BASE}/webs/url_extract_nodupes.txt"
    "${RECON_BASE}/webs/params_discovered.txt"
    "${RECON_BASE}/js/url_extract_js.txt"
    "${RECON_BASE}/js/js_endpoints.txt"
    "${RECON_BASE}/gf/xss.txt"
    "${RECON_BASE}/gf/potential.txt"
    "${RECON_BASE}/fuzzing/fuzzing_full.txt"
    "${RECON_BASE}/hosts/webs.txt"
  )

  # সব file থেকে URL বের করে AllLink.txt এ রাখো
  : > "$ALLLINK_FILE"
  found_sources=0
  for src in "${URL_SOURCES[@]}"; do
    if [[ -f "$src" && -s "$src" ]]; then
      # http/https দিয়ে শুরু হওয়া URL এবং শুধু hostname (subdomain) দুটোই নাও
      grep -aEo 'https?://[^ "'\''<>]+' "$src" >> "$ALLLINK_FILE" 2>/dev/null || true
      # plain hostname/subdomain lines (http ছাড়া) → https:// prefix দিয়ে add করো
      grep -avE '^https?://' "$src" | grep -aE '^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$' \
        | sed 's|^|https://|' >> "$ALLLINK_FILE" 2>/dev/null || true
      found_sources=$((found_sources + 1))
      _dim "  ✓ $(basename $(dirname $src))/$(basename $src)"
    fi
  done

  if [[ $found_sources -eq 0 ]]; then
    _err "CSRRrecon did not produce any URL files under ${RECON_BASE}"
    exit 1
  fi

  ALLLINK_COUNT=$(wc -l < "$ALLLINK_FILE" | tr -d ' ')
  _info "AllLink.txt → ${B}${ALLLINK_COUNT} total URLs${X} collected (with duplicates)"

  # Duplicate remove করে scn1urls.txt তৈরি করো
  sort -u "$ALLLINK_FILE" > "$SCN1URLS_FILE"
  SCN1_COUNT=$(wc -l < "$SCN1URLS_FILE" | tr -d ' ')

  _ok "AllLink.txt  → ${ALLLINK_COUNT} URLs (raw)"
  _ok "scn1urls.txt → ${B}${SCN1_COUNT} URLs${X} (duplicates removed)"
  _dim "Saved: ${ALLLINK_FILE}"
  _dim "Saved: ${SCN1URLS_FILE}"
fi

# ────────────────────────────────────────────────────────────────
#  PHASE 2 — scn1 XSS / Sink Scanner
# ────────────────────────────────────────────────────────────────
if [[ "$SKIP_XSS" == true ]]; then
  _warn "Skipping XSS scan (--skip-xss)"
else
  _step "Phase 2 — XSS / Sink Scanner (scn1)"
  SCN1_COUNT=$(wc -l < "$SCN1URLS_FILE" | tr -d ' ')
  _info "URLs: ${SCN1_COUNT} | Workers: ${CONCURRENCY} | Timeout: ${TIMEOUT}s"
  $USE_BROWSER && _info "Browser mode: ON (Playwright)" || \
    _warn "Browser mode: OFF (use --use-browser for better results)"

  [[ ! -f "${SCN1_DIR}/cli.py" ]] && \
    { _err "scn1 cli.py not found. Run --install first."; exit 1; }

  PAYLOADS="${SCN1_DIR}/payloads.txt"

  CMD=(
    python3 "${SCN1_DIR}/cli.py"
    --subdomains-file "$SCN1URLS_FILE"
    --payloads-file   "$PAYLOADS"
    --output-dir      "$XSS_DIR"
    --concurrency     "$CONCURRENCY"
    --timeout         "$TIMEOUT"
  )
  $USE_BROWSER                && CMD+=(--use-browser)
  [[ -n "$COOKIES" ]]         && CMD+=(--cookies "$COOKIES")
  [[ -n "$HEADERS" ]]         && CMD+=(--headers "$HEADERS")

  _dim "Command: ${CMD[*]}"
  echo ""
  "${CMD[@]}"

  _ok "XSS scan done"
  _dim "Reports: ${XSS_DIR}/"
fi

# ────────────────────────────────────────────────────────────────
#  SUMMARY
# ────────────────────────────────────────────────────────────────
echo ""
echo -e "${B}${G}╔══════════════════════════════════════╗${X}"
echo -e "${B}${G}║         full_scn — DONE ✔            ║${X}"
echo -e "${B}${G}╚══════════════════════════════════════╝${X}"
echo -e "  ${B}Target:${X}      ${DOMAIN:-custom}"
echo -e "  ${B}AllLink:${X}     ${ALLLINK_FILE}"
echo -e "  ${B}scn1urls:${X}    ${SCN1URLS_FILE}"
echo -e "  ${B}XSS Reports:${X} ${XSS_DIR}/"
echo -e "  ${B}All Results:${X} ${RESULTS_DIR}/"
echo ""
