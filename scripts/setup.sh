#!/usr/bin/env bash
# =============================================================================
# Cytadel Sentinel — idempotent tool installer.
#
# Safe to run repeatedly. For every dependency it CHECKS first and installs only
# what is missing, then verifies. Prints a summary table (tool / status /
# version) at the end. Never silently fails: any failed install is reported with
# a reason. Exits non-zero only if a REQUIRED tool failed.
#
# Target platform: Linux or WSL2 (apt-based). Detects the platform and refuses
# to guess on unsupported hosts (native Windows/Git-Bash, macOS) — it will still
# run all detection checks and tell you exactly what is missing.
#
# Usage:  bash scripts/setup.sh            (or: npm run setup)
#         SKIP_DEFECTDOJO=1 bash scripts/setup.sh   # skip bringing up DefectDojo
# =============================================================================
set -uo pipefail

# ------------------------------------------------------------------ paths ----
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TOOLS_DIR="$ROOT_DIR/tools"
GOBIN="${GOBIN:-$HOME/go/bin}"
export PATH="$GOBIN:$PATH"

# ------------------------------------------------------------ result table ---
# Parallel arrays: name / status / detail. Bash 3 compatible (macOS-safe).
declare -a R_NAME R_STATUS R_DETAIL
FAILED_REQUIRED=0

record() { # name  status(OK|INSTALLED|SKIP|OPTIONAL|FAIL)  detail
  R_NAME+=("$1"); R_STATUS+=("$2"); R_DETAIL+=("$3")
  if [ "$2" = "FAIL" ]; then FAILED_REQUIRED=$((FAILED_REQUIRED + 1)); fi
}

log()  { printf '\033[1;36m[setup]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn ]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[error]\033[0m %s\n' "$*"; }

have() { command -v "$1" >/dev/null 2>&1; }

# ----------------------------------------------------------- platform ---------
OS="unknown"; PKG=""
detect_platform() {
  local uname_s; uname_s="$(uname -s 2>/dev/null || echo unknown)"
  case "$uname_s" in
    Linux)
      if grep -qiE "microsoft|wsl" /proc/version 2>/dev/null; then OS="wsl2"; else OS="linux"; fi
      if have apt-get; then PKG="apt"; elif have dnf; then PKG="dnf"; elif have pacman; then PKG="pacman"; fi
      ;;
    Darwin) OS="macos"; have brew && PKG="brew" ;;
    MINGW*|MSYS*|CYGWIN*) OS="windows-bash" ;;
    *) OS="unknown" ;;
  esac
  log "Detected platform: $OS  (package manager: ${PKG:-none})"
}

apt_install() { # pkg...
  if [ "$PKG" != "apt" ]; then return 1; fi
  sudo apt-get update -y >/dev/null 2>&1
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" >/dev/null 2>&1
}

# =============================================================================
# Go toolchain
# =============================================================================
GO_VERSION_PIN="1.23.4"
install_go() {
  if have go; then
    record "go" "OK" "$(go version 2>/dev/null | awk '{print $3}')"
    return 0
  fi
  log "Go not found — installing $GO_VERSION_PIN ..."
  if [ "$PKG" = "apt" ] || [ "$OS" = "wsl2" ] || [ "$OS" = "linux" ]; then
    local tarball="go${GO_VERSION_PIN}.linux-amd64.tar.gz"
    if curl -fsSLo "/tmp/$tarball" "https://go.dev/dl/$tarball" 2>/dev/null; then
      sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf "/tmp/$tarball"
      export PATH="/usr/local/go/bin:$PATH"
      if have go; then
        record "go" "INSTALLED" "$(go version | awk '{print $3}')"
      else
        record "go" "FAIL" "installed to /usr/local/go but not on PATH — add /usr/local/go/bin"
      fi
    else
      record "go" "FAIL" "download failed (network/proxy?) — install Go manually"
    fi
  else
    record "go" "FAIL" "unsupported platform ($OS) — install Go, then re-run in WSL2/Linux"
  fi
}

# =============================================================================
# System libs (naabu needs libpcap)
# =============================================================================
install_libpcap() {
  # Header presence is the real signal naabu cares about.
  if ls /usr/include/pcap/pcap.h >/dev/null 2>&1 || ls /usr/include/pcap.h >/dev/null 2>&1; then
    record "libpcap-dev" "OK" "headers present"
    return 0
  fi
  log "libpcap-dev not found — installing ..."
  if apt_install libpcap-dev; then
    record "libpcap-dev" "INSTALLED" "apt"
  else
    record "libpcap-dev" "FAIL" "install failed — naabu build/run will fail without libpcap"
  fi
}

# =============================================================================
# Go-based ProjectDiscovery / recon tools
# =============================================================================
go_install() { # binName  modulePath@version
  local bin="$1" mod="$2"
  if have "$bin"; then
    record "$bin" "OK" "$("$bin" -version 2>&1 | head -1 | tr -d '\n' || echo present)"
    return 0
  fi
  if ! have go; then
    record "$bin" "FAIL" "go missing — cannot 'go install $mod'"
    return 1
  fi
  log "Installing $bin via go install $mod ..."
  if GOBIN="$GOBIN" go install "$mod" >/tmp/go_install_"$bin".log 2>&1; then
    if have "$bin"; then
      record "$bin" "INSTALLED" "$("$bin" -version 2>&1 | head -1 | tr -d '\n' || echo installed)"
    else
      record "$bin" "FAIL" "installed to $GOBIN but not on PATH — add $GOBIN to PATH"
    fi
  else
    record "$bin" "FAIL" "go install failed — see /tmp/go_install_$bin.log"
  fi
}

install_go_tools() {
  go_install subfinder    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  go_install httpx        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  go_install naabu        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  go_install nuclei       "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  go_install katana       "github.com/projectdiscovery/katana/cmd/katana@latest"
  go_install gau          "github.com/lc/gau/v2/cmd/gau@latest"
  go_install waybackurls  "github.com/tomnomnom/waybackurls@latest"
}

update_nuclei_templates() {
  if have nuclei; then
    log "Updating nuclei templates ..."
    if nuclei -update-templates >/tmp/nuclei_templates.log 2>&1; then
      record "nuclei-templates" "OK" "updated"
    else
      record "nuclei-templates" "FAIL" "update failed — see /tmp/nuclei_templates.log"
    fi
  else
    record "nuclei-templates" "FAIL" "nuclei missing"
  fi
}

# =============================================================================
# git/npm/apt-based tools
# =============================================================================
install_nikto() {
  if have nikto; then record "nikto" "OK" "$(nikto -Version 2>/dev/null | head -1 || echo present)"; return 0; fi
  log "Installing nikto ..."
  if apt_install nikto && have nikto; then
    record "nikto" "INSTALLED" "apt"
  elif git clone --depth 1 https://github.com/sullo/nikto "$TOOLS_DIR/nikto" >/dev/null 2>&1; then
    record "nikto" "INSTALLED" "git -> tools/nikto (run via tools/nikto/program/nikto.pl)"
  else
    record "nikto" "FAIL" "apt+git both failed"
  fi
}

install_testssl() {
  if have testssl.sh; then record "testssl.sh" "OK" "$(testssl.sh --version 2>&1 | head -1 || echo present)"; return 0; fi
  if [ -x "$TOOLS_DIR/testssl.sh/testssl.sh" ]; then
    record "testssl.sh" "OK" "tools/testssl.sh (already cloned)"; return 0
  fi
  log "Cloning testssl.sh ..."
  if git clone --depth 1 https://github.com/drwetter/testssl.sh "$TOOLS_DIR/testssl.sh" >/dev/null 2>&1; then
    record "testssl.sh" "INSTALLED" "git -> tools/testssl.sh/testssl.sh"
  else
    record "testssl.sh" "FAIL" "git clone failed"
  fi
}

install_retirejs() {
  if have retire; then record "retire.js" "OK" "$(retire --version 2>/dev/null | head -1 || echo present)"; return 0; fi
  if ! have npm; then record "retire.js" "FAIL" "npm missing — install Node.js first"; return 1; fi
  log "Installing retire.js (npm -g) ..."
  if npm install -g retire >/tmp/retire_install.log 2>&1 && have retire; then
    record "retire.js" "INSTALLED" "$(retire --version 2>/dev/null | head -1 || echo installed)"
  else
    record "retire.js" "FAIL" "npm install -g retire failed — see /tmp/retire_install.log"
  fi
}

install_wpscan() { # optional
  if have wpscan; then record "wpscan (optional)" "OPTIONAL" "$(wpscan --version 2>/dev/null | head -1 || echo present)"; return 0; fi
  if have gem; then
    log "Installing wpscan (gem, optional) ..."
    if sudo gem install wpscan >/tmp/wpscan_install.log 2>&1 && have wpscan; then
      record "wpscan (optional)" "OPTIONAL" "gem install"
      return 0
    fi
  fi
  record "wpscan (optional)" "OPTIONAL" "not installed — 'gem install wpscan' when needed"
}

# =============================================================================
# Redis + DefectDojo (Docker)
# =============================================================================
ensure_redis() {
  if have redis-server || have redis-cli; then
    record "redis" "OK" "native redis present"
    return 0
  fi
  if ! have docker; then
    record "redis" "FAIL" "no native redis and no docker to run it"
    return 1
  fi
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^sentinel-redis$'; then
    record "redis" "OK" "docker container sentinel-redis running"
    return 0
  fi
  log "Starting Redis via Docker (sentinel-redis on :6379) ..."
  if docker run -d --name sentinel-redis -p 6379:6379 --restart unless-stopped redis:7-alpine >/dev/null 2>&1; then
    record "redis" "INSTALLED" "docker sentinel-redis :6379"
  else
    # Container may already exist but be stopped.
    if docker start sentinel-redis >/dev/null 2>&1; then
      record "redis" "OK" "docker sentinel-redis restarted"
    else
      record "redis" "FAIL" "docker run redis failed"
    fi
  fi
}

bring_up_defectdojo() {
  if [ "${SKIP_DEFECTDOJO:-0}" = "1" ]; then
    record "defectdojo" "SKIP" "SKIP_DEFECTDOJO=1"
    return 0
  fi
  if ! have docker; then
    record "defectdojo" "FAIL" "docker required for DefectDojo"
    return 1
  fi
  local compose_dir="$ROOT_DIR/docker/defectdojo"
  local dc
  if docker compose version >/dev/null 2>&1; then dc="docker compose"; elif have docker-compose; then dc="docker-compose"; else
    record "defectdojo" "FAIL" "docker compose plugin not available"; return 1
  fi

  log "Bringing up DefectDojo ($dc up -d) — first boot pulls images + migrates, be patient ..."
  if ! ( cd "$compose_dir" && $dc up -d ) >/tmp/defectdojo_up.log 2>&1; then
    record "defectdojo" "FAIL" "compose up failed — see /tmp/defectdojo_up.log"
    return 1
  fi

  log "Waiting for DefectDojo to become healthy (up to ~5 min) ..."
  local url="http://localhost:8080/login?next=/"
  local i
  for i in $(seq 1 60); do
    if curl -fsS -o /dev/null "$url" 2>/dev/null; then
      record "defectdojo" "INSTALLED" "healthy at http://localhost:8080"
      log "DefectDojo is up: http://localhost:8080"
      log "Admin password (first boot): ( cd $compose_dir && $dc logs initializer | grep -i 'Admin password' )"
      log "API key: log in -> top-right user menu -> 'API v2 Key' -> put it in .env as DEFECTDOJO_API_KEY"
      return 0
    fi
    sleep 5
  done
  record "defectdojo" "FAIL" "did not become healthy in time — check '$dc logs' in $compose_dir"
}

# =============================================================================
# Summary
# =============================================================================
print_summary() {
  echo
  printf '\033[1m%s\033[0m\n' "==================== Cytadel Sentinel — setup summary ===================="
  printf '%-22s %-11s %s\n' "TOOL" "STATUS" "DETAIL"
  printf '%-22s %-11s %s\n' "----" "------" "------"
  local i color
  for i in "${!R_NAME[@]}"; do
    case "${R_STATUS[$i]}" in
      OK|INSTALLED) color="\033[1;32m" ;;   # green
      OPTIONAL|SKIP) color="\033[1;33m" ;;   # yellow
      FAIL) color="\033[1;31m" ;;            # red
      *) color="\033[0m" ;;
    esac
    printf "${color}%-22s %-11s\033[0m %s\n" "${R_NAME[$i]}" "${R_STATUS[$i]}" "${R_DETAIL[$i]}"
  done
  echo   "=========================================================================="
  if [ "$FAILED_REQUIRED" -gt 0 ]; then
    err "$FAILED_REQUIRED required tool(s) failed. Fix the FAIL rows above and re-run (safe: idempotent)."
    if [ "$OS" = "windows-bash" ] || [ "$OS" = "macos" ] || [ "$OS" = "unknown" ]; then
      warn "This host ($OS) is not the supported target. Run this script inside WSL2 or a Linux box."
    fi
  else
    log "All required tools present. Add '$GOBIN' and '/usr/local/go/bin' to your shell PATH if not already."
  fi
}

# =============================================================================
# Main
# =============================================================================
main() {
  mkdir -p "$TOOLS_DIR" "$ROOT_DIR/reports" "$ROOT_DIR/audit"
  detect_platform

  if [ "$OS" = "windows-bash" ]; then
    warn "Running under Git-Bash/MSYS on Windows. apt/go-install/native builds are NOT supported here."
    warn "Detection will still run so you can see what's missing, but installs will be marked FAIL."
    warn "For a real install, use WSL2:  wsl --install  then re-run this script inside Ubuntu."
  fi

  install_go
  install_libpcap
  install_go_tools
  update_nuclei_templates
  install_nikto
  install_testssl
  install_retirejs
  install_wpscan
  ensure_redis
  bring_up_defectdojo

  print_summary
  [ "$FAILED_REQUIRED" -eq 0 ]
}

main "$@"
