#!/usr/bin/env bash
# AnyLink One-Key Installer v3.5 — Debian 12+
# - Auto-detect ipv4_master (eg. default route iface)
# - Force-free ports 80/443/8800 (stop services / kill PIDs)

[[ "${DEBUG:-0}" == "1" ]] && set -x
set -euo pipefail

# ---------- Pretty printing ----------
STEP(){ echo -e "\n\033[1;36m[$1] $2\033[0m"; }
OK(){   echo -e "\033[1;32m[OK]\033[0m $*"; }
WARN(){ echo -e "\033[1;33m[WARN]\033[0m $*"; }
ERR(){  echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }

# ---------- Constants ----------
ANYLINK_DIR="/usr/local/anylink-deploy"
SERVICE="anylink.service"
SYSTEMD_DIR="/etc/systemd/system"
ADMIN_PLAIN_PASS="freedom123"

# ---------- Helpers ----------
need(){
  if ! command -v "$1" >/dev/null 2>&1; then
    STEP "0" "Installing dependency: $1"
    DEBIAN_FRONTEND=noninteractive apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$2"
  fi
}
require_root(){ [[ $EUID -eq 0 ]] || { ERR "Please run as root."; exit 1; }; }
require_debian12(){
  . /etc/os-release
  if [[ "${ID:-}" != "debian" || "${VERSION_ID%%.*}" -lt 12 ]]; then
    ERR "Debian 12+ is required (detected: ${ID:-?} ${VERSION_ID:-?})."
    exit 1
  fi
}
get_latest_tag(){
  # Follow redirect to the concrete latest release URL and grab the last path segment (vX.Y.Z)
  curl -fsSLI -o /dev/null -w '%{url_effective}\n' https://github.com/bjdgyc/anylink/releases/latest | awk -F/ '{print $NF}'
}
map_arch(){
  case "$(dpkg --print-architecture)" in
    amd64) echo linux-amd64;;
    arm64) echo linux-arm64;;
    *) ERR "Unsupported architecture: $(dpkg --print-architecture)"; exit 1;;
  esac
}
toml_set(){
  local k="$1" v="$2" f="$3"
  if grep -Eq "^\s*${k}\s*=" "$f"; then
    sed -i -E "s|^(\s*${k}\s*=\s*).*$|\1\"${v}\"|" "$f"
  else
    echo "${k} = \"${v}\"" >> "$f"
  fi
}
detect_iface(){
  # Prefer interface from default route, fallback to route to 1.1.1.1, else eth0
  local dev
  dev="$(ip -4 route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
  [[ -n "$dev" ]] || dev="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
  [[ -n "$dev" ]] || dev="eth0"
  echo "$dev"
}

# ---------- Force-free ports ----------
_stop_guess_service(){
  local comm="$1"
  for svc in "$comm" "${comm}.service" nginx apache2 caddy haproxy docker-proxy anylink; do
    systemctl stop "$svc" 2>/dev/null && return 0 || true
  done
  return 1
}
_kill_pid_tree(){
  local pid="$1"
  kill -TERM "$pid" 2>/dev/null || true
  for _ in 1 2 3; do sleep 0.5; kill -0 "$pid" 2>/dev/null || return 0; done
  kill -KILL "$pid" 2>/dev/null || true
}
force_free_port(){
  local port="$1" lines
  lines="$(ss -ltnp 2>/dev/null | awk -v p=":$port" '$4~p')"
  [[ -n "$lines" ]] || { OK "Port $port is free."; return 0; }
  STEP "0" "Force free port: $port"; echo "$lines"
  mapfile -t pids < <(ss -ltnp 2>/dev/null \
    | awk -v p=":$port" '$4~p {for(i=1;i<=NF;i++) if ($i ~ /pid=/){sub(/.*pid=/,"",$i); sub(/,.*/,"",$i); print $i}}' \
    | sort -u)
  for pid in "${pids[@]}"; do
    [[ -d "/proc/$pid" ]] || continue
    local cmd comm base
    cmd="$(tr '\0' ' ' </proc/$pid/cmdline 2>/dev/null || true)"
    comm="$(cat /proc/$pid/comm 2>/dev/null || true)"
    base="$(basename "${cmd%% *}")"; [[ -n "$base" ]] || base="$comm"
    echo "  - PID=$pid process: $base   CMD: ${cmd:0:120}"
    _stop_guess_service "$base" && echo "    Tried stopping service: $base" || true
    if ss -ltnp 2>/dev/null | grep -q ":$port " | grep -q "pid=$pid"; then
      echo "    Still listening, killing PID: $pid"
      _kill_pid_tree "$pid"
    fi
  done
  if ss -ltnp 2>/dev/null | awk -v p=":$port" '$4~p {exit 1}'; then
    OK "Port $port has been freed."
  else
    ERR "Port $port is still occupied. Please investigate."
    exit 1
  fi
}
force_free_ports(){ for p in 80 443 8800; do force_free_port "$p"; done; }

# ---------- Detect existing install / uninstall ----------
already_installed(){
  [[ -x "$ANYLINK_DIR/anylink" ]] && return 0
  systemctl list-unit-files | grep -q "^${SERVICE}" && return 0
  return 1
}
uninstall_all(){
  STEP "0" "Uninstalling existing AnyLink"
  systemctl stop "$SERVICE" 2>/dev/null || true
  systemctl disable "$SERVICE" 2>/dev/null || true
  rm -f "$SYSTEMD_DIR/$SERVICE" "/usr/lib/systemd/system/$SERVICE" "/lib/systemd/system/$SERVICE" || true
  systemctl daemon-reload || true
  systemctl reset-failed || true
  rm -rf "$ANYLINK_DIR" || true
  OK "Uninstall complete."
}

# ---------- 0: Dependencies & baseline ----------
precheck(){
  STEP "0" "Checking/installing dependencies"
  need curl curl
  need wget wget
  need tar tar
  need systemctl systemd
  need sed sed
  need awk gawk
  need openssl openssl || true
  need ss iproute2
  need iptables iptables
  need xmlstarlet xmlstarlet
  update-ca-certificates || true

  STEP "0" "Checking existing AnyLink installation"
  if already_installed; then
    read -rp "AnyLink appears installed. Uninstall it before continuing? [y/N]: " a; a="${a:-N}"
    [[ "$a" =~ ^[Yy]$ ]] || { ERR "User chose not to uninstall. Aborting."; exit 1; }
    uninstall_all
  else
    OK "No existing AnyLink installation found."
  fi
}

pre_network(){
  STEP "0" "Network/kernel preparation"
  force_free_ports
  if [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)" != "1" ]]; then
    sysctl -w net.ipv4.ip_forward=1 >/dev/null || true
    sed -i '/^net.ipv4.ip_forward/d' /etc/sysctl.conf || true
    echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
    OK "Enabled IPv4 forwarding."
  fi
  [[ -c /dev/net/tun ]] || WARN "/dev/net/tun not found. If AnyLink fails, run: modprobe tun && echo tun >/etc/modules-load.d/tun.conf"
}

# ---------- 1: Certificates (fixed 1.pem / 1.key) ----------
prompt_domain(){
  STEP "1" "Domain"
  read -rp "Enter your domain already pointing to this host (used for 443/8800): " DOMAIN
  [[ -n "${DOMAIN:-}" ]] || { ERR "Domain must not be empty."; exit 1; }
  echo "$DOMAIN" > /tmp/.anylink_domain
  OK "Domain: $DOMAIN"
}

apply_cert(){
  STEP "1.1" "Issue SSL certificate (domainSSL)"
  printf '%s\n' "$DOMAIN" | bash <(curl -s -L git.io/dmSSL)
  CERT_DIR="/home/ssl/$DOMAIN"
  [[ -d "$CERT_DIR" ]] || { ERR "Certificate directory not found: $CERT_DIR"; exit 1; }
  OK "Certificate directory: $CERT_DIR"
}

pick_cert(){
  STEP "1.2" "Locate certificate files (fixed names)"
  CERT_FILE="$CERT_DIR/1.pem"
  KEY_FILE="$CERT_DIR/1.key"
  [[ -f "$CERT_FILE" && -f "$KEY_FILE" ]] || { ERR "Missing $CERT_FILE or $KEY_FILE"; exit 1; }
  OK "Certificate: $CERT_FILE"
  OK "Private key: $KEY_FILE"
}

verify_cert(){
  STEP "1.3" "Verify certificate (openssl)"
  if ! openssl x509 -in "$CERT_FILE" -noout -subject -issuer -dates >/tmp/.certinfo 2>&1; then
    ERR "Failed to parse certificate: $CERT_FILE"
    cat /tmp/.certinfo
    exit 1
  fi
  cat /tmp/.certinfo
  OK "Certificate looks valid. Proceeding."
}

# ---------- 2/3: Download & extract AnyLink ----------
download_anylink(){
  STEP "2" "Download AnyLink (latest release)"
  TAG="$(get_latest_tag)"; VER="${TAG#v}"; ARCH="$(map_arch)"
  PKG="anylink-${VER}-${ARCH}.tar.gz"
  URL="https://github.com/bjdgyc/anylink/releases/download/${TAG}/${PKG}"
  OK "Version: $TAG  Arch: $ARCH"
  TMPD="$(mktemp -d)"; trap '[[ -n "${TMPD:-}" ]] && rm -rf "$TMPD"' RETURN
  (cd "$TMPD" && wget -q --show-progress "$URL")
  STEP "3" "Extract to /usr/local"
  tar -xzvf "$TMPD/$PKG" -C /usr/local/
  [[ -x "$ANYLINK_DIR/anylink" ]] || { ERR "AnyLink binary not found after extraction: $ANYLINK_DIR/anylink"; exit 1; }
  OK "Extraction complete: $ANYLINK_DIR"
}

# ---------- 4/5: Generate password hash & JWT secret ----------
gen_secrets(){
  STEP "4" "Generate admin password hash"
  PASS_HASH="$("$ANYLINK_DIR/anylink" tool -p "$ADMIN_PLAIN_PASS" | sed -n 's/^Passwd://p' | tr -d '[:space:]')"
  [[ -n "$PASS_HASH" ]] || { ERR "Failed to generate admin password hash."; exit 1; }
  echo "$PASS_HASH" > /tmp/.anylink_admin_hash
  echo "  hash (masked): ${PASS_HASH:0:12}...${PASS_HASH: -8}"

  STEP "5" "Generate JWT secret"
  JWT_SECRET="$("$ANYLINK_DIR/anylink" tool -s | sed -n 's/^Secret://p' | tr -d '[:space:]')"
  [[ -n "$JWT_SECRET" ]] || { ERR "Failed to generate jwt_secret."; exit 1; }
  echo "$JWT_SECRET" > /tmp/.anylink_jwt_secret
  echo "  jwt_secret (masked): ${JWT_SECRET:0:8}...${JWT_SECRET: -6}"
}

# ---------- 6/7/8: Write config (server.toml + profile.xml) ----------
write_conf(){
  STEP "6" "Prepare conf directory & copy template"
  cd "$ANYLINK_DIR/conf"
  cp -f server-sample.toml server.toml

  STEP "7/8" "Write cert_file/cert_key/admin_pass/jwt_secret/ipv4_master/link_addr"
  local IFACE; IFACE="$(detect_iface)"
  toml_set cert_file   "$CERT_FILE" server.toml
  toml_set cert_key    "$KEY_FILE"  server.toml
  toml_set admin_pass  "$(cat /tmp/.anylink_admin_hash)" server.toml
  toml_set jwt_secret  "$(cat /tmp/.anylink_jwt_secret)" server.toml
  toml_set ipv4_master "$IFACE" server.toml
  toml_set link_addr   "${DOMAIN}:443" server.toml || true

  echo "  cert_file   = $(grep -E '^ *cert_file'   server.toml | awk -F= '{print $2}')"
  echo "  cert_key    = $(grep -E '^ *cert_key'    server.toml | awk -F= '{print $2}')"
  echo "  ipv4_master = $(grep -E '^ *ipv4_master' server.toml | awk -F= '{print $2}')"
  echo "  admin_pass  = (bcrypt hash written)"
  echo "  jwt_secret  = (written)"
  echo "  link_addr   = ${DOMAIN}:443"

  # profile.xml: keep exactly ONE <HostEntry> with VPN / <domain>:443
  if [[ -f profile.xml ]]; then
    cp -a profile.xml "profile.xml.bak.$(date +%F-%H%M%S)"
    # Remove ALL HostEntry nodes
    xmlstarlet ed -P -L -d '//HostEntry' profile.xml
    # Add a single HostEntry at document root, then add children HostName and HostAddress
    xmlstarlet ed -P -L \
      -s '/*' -t elem -n 'HostEntry' -v '' \
      -s '(//HostEntry)[1]' -t elem -n 'HostName' -v 'VPN' \
      -s '(//HostEntry)[1]' -t elem -n 'HostAddress' -v "${DOMAIN}:443" \
      profile.xml
    OK "profile.xml normalized to a single HostEntry: VPN / ${DOMAIN}:443"
  else
    WARN "profile.xml not found; skipping."
  fi

  OK "server.toml / profile.xml updated."
}

# ---------- 9: systemd install ----------
install_service(){
  STEP "9" "Install systemd unit and enable on boot"
  local SRC=""
  [[ -f "$ANYLINK_DIR/systemd/anylink.service" ]] && SRC="$ANYLINK_DIR/systemd/anylink.service"
  [[ -z "$SRC" && -f "$ANYLINK_DIR/deploy/anylink.service" ]] && SRC="$ANYLINK_DIR/deploy/anylink.service"
  [[ -n "$SRC" ]] || { ERR "anylink.service template not found (systemd/ or deploy/)."; exit 1; }

  mkdir -p "$SYSTEMD_DIR"
  cp -f "$SRC" "$SYSTEMD_DIR/$SERVICE"

  # Ensure PATH for the unit (iptables and others may be in /usr/sbin)
  if ! grep -q '^Environment=PATH=' "$SYSTEMD_DIR/$SERVICE"; then
    sed -i '/^\[Service\]/a Environment=PATH=/usr/sbin:/usr/bin:/sbin:/bin' "$SYSTEMD_DIR/$SERVICE"
  fi

  systemctl daemon-reload
  systemctl enable "$SERVICE"
  OK "Enabled: $SERVICE"
}

# ---------- 10: start & verify ----------
start_and_verify(){
  STEP "10" "Start AnyLink"
  systemctl start "$SERVICE" || true
  sleep 1
  if ! systemctl is-active --quiet "$SERVICE"; then
    ERR "Service failed to start. Last 200 lines of logs:"
    journalctl -u "$SERVICE" -n 200 --no-pager || true
    echo
    WARN "Quick checklist:"
    echo "  - Certificate/key permission/format (fixed to 1.pem/1.key)"
    echo "  - Ports 443/8800 occupied (script tried to free them)"
    echo "  - /dev/net/tun missing or ip_forward disabled"
    echo "  - server.toml syntax (quotes, spaces in paths)"
    echo
    echo "Run in foreground for debugging:"
    echo "  $ANYLINK_DIR/anylink --conf=$ANYLINK_DIR/conf/server.toml"
    exit 1
  fi
  OK "Service is active."
}

# ---------- 11: summary ----------
summary(){
  STEP "11" "Admin panel"
  DOMAIN="$(cat /tmp/.anylink_domain)"
  echo "  URL: https://${DOMAIN}:8800"
  echo "  User: admin"
  echo "  Pass: ${ADMIN_PLAIN_PASS}"
  echo
  echo "Other commands:"
  echo "  systemctl restart anylink   # restart"
  echo "  systemctl status anylink    # status"
}

# ----------------- Main flow -----------------
require_root
require_debian12

# 0. deps & baseline
precheck
pre_network

# 1. certificates (fixed 1.pem/1.key)
prompt_domain
apply_cert
pick_cert
verify_cert

# 2/3. download & extract
download_anylink

# 4/5. secrets
gen_secrets

# 6/7/8. configs (server.toml + profile.xml)
write_conf

# 9. systemd
install_service

# 10. start & verify
start_and_verify

# 11. summary
summary
