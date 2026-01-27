#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# ==========================================================
# TomattoVPN TUNNELING — RAPiH + FIX (tetap berfungsi)
# - Tanda perubahan:
#   # ASLI: ...
#   # FIX : ...
# ==========================================================

# =========================
# 0) Helper (rapi & aman)
# =========================
log(){ echo -e "$*"; }
die(){ echo -e "\e[1;31m[ERROR]\e[0m $*"; exit 1; }

systemctl_try(){ systemctl "$@" >/dev/null 2>&1 || true; }
service_try(){ /etc/init.d/"$1" "$2" >/dev/null 2>&1 || true; }
cmd_try(){ "$@" >/dev/null 2>&1 || true; }

wait_apt_lock(){
  local locks=(
    /var/lib/dpkg/lock-frontend
    /var/lib/dpkg/lock
    /var/cache/apt/archives/lock
  )
  local i
  for i in {1..60}; do
    local busy=0
    for f in "${locks[@]}"; do
      if fuser "$f" >/dev/null 2>&1; then busy=1; fi
    done
    [ "$busy" -eq 0 ] && return 0
    sleep 2
  done
  die "APT/DPKG lock masih aktif. Coba tunggu lalu jalankan lagi."
}

# =========================
# 1) Cek basic
# =========================
[ "${EUID:-$(id -u)}" -eq 0 ] || die "Jalankan sebagai root."

if [ "$(systemd-detect-virt 2>/dev/null || true)" = "openvz" ]; then
  die "OpenVZ tidak disupport."
fi

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|aarch64) : ;;
  *) die "Arsitektur tidak disupport: $ARCH" ;;
esac

OS_ID="$(. /etc/os-release && echo "${ID}")"
OS_VER="$(. /etc/os-release && echo "${VERSION_ID}")"
OS_PRETTY="$(. /etc/os-release && echo "${PRETTY_NAME}")"

case "$OS_ID" in
  ubuntu|debian) : ;;
  *) die "OS tidak disupport: $OS_PRETTY" ;;
esac

# =========================
# 2) Matikan apt-daily (lebih rapi)
# =========================
systemctl_try stop    apt-daily.timer apt-daily-upgrade.timer
systemctl_try disable apt-daily.timer apt-daily-upgrade.timer
systemctl_try stop    apt-daily.service apt-daily-upgrade.service
systemctl_try mask    apt-daily.service apt-daily-upgrade.service

wait_apt_lock
cmd_try dpkg --configure -a

# =========================
# 3) Update + paket awal
# =========================
apt-get update -y
apt-get upgrade -y

# FIX: tambahin lsof/iptables-persistent/netfilter-persistent biar pasang_ssl & firewall gak gagal
apt-get install -y \
  curl wget unzip zip ca-certificates gnupg lsb-release software-properties-common \
  net-tools iproute2 dnsutils jq lsof cron \
  iptables iptables-persistent netfilter-persistent

# ASLI: apt-get install lolcat wondershaper (bisa fail di beberapa repo)
# FIX : jadikan optional supaya script tetap lanjut
apt-get install -y lolcat wondershaper >/dev/null 2>&1 || true

# Pastikan user www-data ada (umumnya sudah ada di Debian/Ubuntu)
if ! id -u www-data >/dev/null 2>&1; then
  useradd -r -s /usr/sbin/nologin -M www-data
fi

# =========================
# 4) Variabel warna (punyamu tetap)
# =========================
Green="\e[92;1m"
RED="\033[1;31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${Green}--->${FONT}"
ERROR="${RED}[ERROR]${FONT}"
GRAY="\e[1;30m"
NC='\e[0m'
red='\e[1;31m'
green='\e[0;32m'
BlueBee="\e[94;1m"
CYAN="\e[96;1m"
COLOR1="\e[92;1m"

# =========================
# 5) Info awal
# =========================
NET="$(ip route | awk '/default/ {print $5; exit}')"
# FIX: kalau NET kosong, kasih default agar vnstat tidak crash
[ -n "${NET:-}" ] || NET="eth0"

valid="$(date +"%Y-%m-%d")"
# FIX: today harus didefinisikan SEBELUM dipakai (set -u)
today="$(date -d "0 days" +"%Y-%m-%d")"
DATE="$(date +'%Y-%m-%d')"
TIME="$(date '+%d %b %Y')"

# ASLI: ipsaya=$(wget -qO- ipinfo.io/ip || true)
# FIX : pakai https
ipsaya="$(wget -qO- https://ipinfo.io/ip || true)"

# IP utama
export IP="$(curl -sS icanhazip.com || true)"
MYIP="$(curl -sS ipv4.icanhazip.com || true)"
[ -n "${MYIP:-}" ] || MYIP="${IP:-}"

# Telegram (isi manual)
TIMES="10"
CHATID="5423129090"          # <-- chat id kamu
KEY="8308467181:AAG_3Ve3XBjr4_rX86gmNcmi9o-WXbVLcqo"  # <-- bot token kamu
URL="https://api.telegram.org/bot${KEY}/sendMessage"


clear
log -e "${BlueBee}╔════════════════════════════════════════════════╗${NC}"
log -e "\033[96;1m                TomattoVPN TUNNELING               \033[0m"
log -e "${BlueBee}╚════════════════════════════════════════════════╝${NC}"
log ""

log -e "\e[94;1m╔═════════════════════════════════════════════════╗${NC}"
log -e "${OK} Architecture: ${green}${ARCH}${NC}"
log -e "${OK} OS          : ${green}${OS_PRETTY}${NC}"
log -e "${OK} IP          : ${green}${IP:-unknown}${NC}"
log -e "\e[94;1m╚═════════════════════════════════════════════════╝ ${NC}"
log ""
sleep 3

# =========================
# 6) Ambil data izin (aman untuk pipefail)
# =========================
IZIN_URL="https://raw.githubusercontent.com/rwrtx/vvipsc/main/izin"
izin_data="$(curl -fsSL "$IZIN_URL" 2>/dev/null || true)"

rm -f /usr/bin/user /usr/bin/e || true

username="$(awk -v ip="$MYIP" '$1==ip{print $2; exit}' <<<"$izin_data")"
expx="$(awk -v ip="$MYIP" '$1==ip{print $3; exit}' <<<"$izin_data")"
Exp1="$(awk -v ip="$MYIP" '$1==ip{print $4; exit}' <<<"$izin_data")"

[ -n "${username:-}" ] || username="unknown"
[ -n "${expx:-}" ] || expx="unknown"
[ -n "${Exp1:-}" ] || Exp1="1970-01-01"

echo "$username" >/usr/bin/user
echo "$expx" >/usr/bin/e

oid="$(cat /usr/bin/ver 2>/dev/null || true)"
exp="$(cat /usr/bin/e || true)"

# =========================
# 7) Hitung status exp (FIX set -u)
# =========================
# ASLI: d2=$(date -d "$today" +%s) tapi today belum didefinisikan
# FIX : today sudah di atas
d1="$(date -d "$valid" +%s)"
d2="$(date -d "$today" +%s)"
certifacate=$(((d1 - d2) / 86400)) || true

datediff() {
  local a b
  a="$(date -d "$1" +%s)"
  b="$(date -d "$2" +%s)"
  echo -e "$COLOR1 $NC Expiry In   : $(( (a - b) / 86400 )) Days"
}

Info="(${green}Active${NC})"
Error="(${RED}ExpiRED${NC})"
if [[ "${today}" < "${Exp1}" ]]; then
  sts="${Info}"
else
  sts="${Error}"
fi

REPO="https://raw.githubusercontent.com/rwrtx/sctomatto/main/"
NOOBZJSON="https://raw.githubusercontent.com/rwrtx/noobzvpns/main/"

start="$(date +%s)"
secs_to_human() {
  echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}

function print_ok()      { echo -e "${OK} ${BLUE} $1 ${FONT}"; }
function print_install() { echo -e "${BlueBee}╔════════════════════════════════════════════════╗${NC}"; echo -e "${CYAN} [•]  $1 ${FONT}"; echo -e "${BlueBee}╚════════════════════════════════════════════════╝${NC}"; sleep 1; }
function print_error()   { echo -e "${ERROR} ${REDBG} $1 ${FONT}"; }
function print_success() { if [[ 0 -eq $? ]]; then echo -e "${BlueBee}╔════════════════════════════════════════════════╗${NC}"; echo -e "${Green}                 INSTALL SUCCESS  ${FONT}"; echo -e "${BlueBee}╚════════════════════════════════════════════════╝${NC}"; sleep 1; fi; }

# =========================
# 8) Setup awal folder xray (rapi)
# =========================
print_install "Membuat direktori xray"
mkdir -p /etc/xray
curl -sS ifconfig.me > /etc/xray/ipvps || true
touch /etc/xray/domain
mkdir -p /var/log/xray
chown -R www-data:www-data /var/log/xray || true
chmod 755 /var/log/xray
touch /var/log/xray/access.log /var/log/xray/error.log
mkdir -p /var/lib/kyt >/dev/null 2>&1

# FIX: init variabel sebelum dipakai (lebih aman)
mem_used=0
mem_total=0
while IFS=":" read -r a b; do
  case $a in
    "MemTotal") ((mem_used+=${b/kB})); mem_total="${b/kB}" ;;
    "Shmem") ((mem_used+=${b/kB})) ;;
    "MemFree" | "Buffers" | "Cached" | "SReclaimable")
      mem_used="$((mem_used-=${b/kB}))"
    ;;
  esac
done < /proc/meminfo

Ram_Usage="$((mem_used / 1024))"
Ram_Total="$((mem_total / 1024))"

export tanggal="$(date -d "0 days" +"%d-%m-%Y - %X")"
export OS_Name="$(grep -w PRETTY_NAME /etc/os-release | head -n1 | cut -d= -f2- | tr -d '"')"
export Kernel="$(uname -r)"
export Arch="$(uname -m)"
export IP="$(curl -sS https://ipinfo.io/ip/ || true)"

# =========================
# 9) Functions
# =========================
function first_setup(){
  clear
  print_install "Initial System Setup"

  timedatectl set-timezone Asia/Jakarta || true

  echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
  echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

  OS_ID="$(grep -w ID /etc/os-release | head -n1 | cut -d= -f2 | tr -d '"')"
  OS_NAME="$(grep -w PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')"
  echo "Setup dependencies for $OS_NAME"

  apt install -y software-properties-common curl gnupg lsb-release

  echo "Installing HAProxy from official OS repository"
  apt install -y haproxy
  systemctl enable haproxy || true

  print_success "Base system & HAProxy installed"
}

function nginx_install() {
  local id
  id="$(grep -w ID /etc/os-release | head -n1 | cut -d= -f2 | tr -d '"')"

  print_install "Setup nginx For OS Is $(grep -w PRETTY_NAME /etc/os-release | head -n1 | cut -d= -f2- | tr -d '"')"

  # ASLI: sudo apt-get install nginx -y
  # FIX : jangan sudo (kamu sudah root)
  if [[ "$id" == "ubuntu" ]]; then
    apt-get install -y nginx
  elif [[ "$id" == "debian" ]]; then
    apt-get install -y nginx
  else
    echo -e " Your OS Is Not Supported ( ${YELLOW}$(grep -w PRETTY_NAME /etc/os-release | head -n1 | cut -d= -f2- | tr -d '"')${FONT} )"
  fi
}

function base_package() {
  clear
  print_install "Menginstall Packet Yang Dibutuhkan"

  apt install -y at zip pwgen openssl netcat socat cron bash-completion figlet git sudo debconf-utils

  apt dist-upgrade -y

  # Ruby (tetap)
  apt install -y ruby ruby-dev rubygems-integration || true

  # ASLI: systemctl enable chronyd (sering gak ada -> script stop)
  # FIX : amanin dengan try
  apt install -y chrony ntpdate
  systemctl_try enable chrony
  systemctl_try restart chrony
  systemctl_try enable chronyd
  systemctl_try restart chronyd

  cmd_try chronyc sourcestats -v
  cmd_try chronyc tracking -v
  cmd_try ntpdate pool.ntp.org

  # Buang mail server & firewall bawaan (tetap)
  apt-get remove --purge -y exim4 || true
  apt-get remove --purge -y ufw firewalld || true

  apt-get install -y --no-install-recommends software-properties-common

  echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
  echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

  # Paket besar (tetap, tapi buat kompatibel Debian/Ubuntu)
  apt-get install -y \
    speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config libpam0g-dev \
    libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make \
    libnss3-tools libevent-dev bc rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev \
    sed dirmngr libxml-parser-perl build-essential gcc g++ \
    python3 python3-pip \
    htop lsof tar wget curl zip unzip p7zip-full \
    libc6 util-linux msmtp-mta ca-certificates bsd-mailx \
    iptables iptables-persistent netfilter-persistent net-tools openssl \
    gnupg gnupg2 lsb-release shc cmake screen socat xz-utils apt-transport-https \
    dnsutils cron bash-completion ntpdate chrony jq openvpn easy-rsa

  apt-get clean -y || true
  apt-get autoremove -y || true

  print_success "Packet Yang Dibutuhkan"
}

function pasang_domain() {
  clear
  echo -e "\e[94;1m╔════════════════════════════════════════════════╗ \e[0m"
  echo -e "                  \e[92;1m DOMAIN MENU \e[0m  "
  echo -e "\e[94;1m╚════════════════════════════════════════════════╝ \e[0m"
  echo -e ""
  echo -e "               \e[1;32m1)\e[0m Input Your Domain"
  echo -e "               \e[1;32m2)\e[0m Random Domain "
  echo -e ""
  echo -e "\e[94;1m╚═════════════════════════════════════════════════╝ \e[0m"
  echo
  read -p "   Please select numbers 1-2 or Any Button(Random) : " host
  echo ""

  if [[ "${host}" == "1" ]]; then
    clear
    echo -e "\e[94;1m╔═════════════════════════════════════════════════╗${NC}"
    echo -e "\e[1;32m                 INPUT YOUR DOMAIN ${NC}"
    echo -e "\e[94;1m╚═════════════════════════════════════════════════╝ ${NC}"
    echo -e ""
    echo -e "\e[91;1m WARNING !! \e[0m"
    echo -e "\e[92;1m  # \e[97;1mPastikan Domain anda udah di pointing \e[0m"
    echo -e "\e[92;1m  # \e[97;1mPastikan ipvps ter pointing ke domain \e[0m"
    echo -e ""
    read -p "   INPUT YOUR DOMAIN :   " host1

    echo "IP=" >> /var/lib/kyt/ipvps.conf
    echo "$host1" > /etc/xray/domain
    echo "$host1" > /root/domain

  elif [[ "${host}" == "2" ]]; then
    cd /root
    wget -q "${REPO}Fls/cf.sh" -O /root/cf.sh
    chmod +x /root/cf.sh
    /root/cf.sh
    rm -f /root/cf.sh
  else
    print_install "Random Subdomain/Domain is Used"
  fi
}

# INFO ISP VPS
ISP="$(cat /etc/xray/isp 2>/dev/null || true)"
# ASLI: CITY=... || true))  (ada 1 kurung lebih -> SYNTAX ERROR)
# FIX :
CITY="$(cat /etc/xray/city 2>/dev/null || true)"
IPVPS="$(curl -sS ipv4.icanhazip.com || true)"
domain="$(cat /etc/xray/domain 2>/dev/null || true)"
RAM="$(free -m | awk 'NR==2 {print $2}')"
USAGERAM="$(free -m | awk 'NR==2 {print $3}')"
MEMOFREE="$(free -m | awk 'NR==2{printf "%.2f%%", $3*100/$2 }')"
LOADCPU="$(top -bn1 | awk '/Cpu/ { print 100 - $8 "%" }' | tail -n1)"
MODEL="$(grep -w PRETTY_NAME /etc/os-release | head -n1 | cut -d= -f2- | tr -d '"')"
CORE="$(grep -c cpu[0-9] /proc/stat)"
DATEVPS="$(date +'%d/%m/%Y')"
TIMEZONE="$(date +'%H:%M:%S')"
SERONLINE="$(uptime -p | cut -d " " -f 2-10000)"

restart_system() {
  # FIX: kalau CHATID/KEY kosong, skip (biar gak “gagal tapi diam-diam”)
  [ -n "${CHATID}" ] || return 0
  [ -n "${KEY}" ] || return 0

  local tzone text
  tzone="$(date +'%H:%M:%S')"

  text="
<code>────────────────────</code>
<b>⚡AUTOSCRIPT PREMIUM⚡</b>
<code>────────────────────</code>
<code>Owner    :</code><code>${username}</code>
<code>OS LINUX :</code><code>${MODEL}</code>
<code>Domain   :</code><code>${domain}</code>
<code>IP VPS   :</code><code>${MYIP}</code>
<code>DATE     :</code><code>${DATE}</code>
<code>Time     :</code><code>${tzone}</code>
<code>Exp Sc.  :</code><code>${exp}</code>
<code>────────────────────</code>
<b> ❖ TomattoVPN  TUNNELING ❖  </b>
<code>────────────────────</code>
<i>Automatic Notifications From Github</i>
"

  curl -s --max-time "${TIMES}" \
    -d "chat_id=${CHATID}" \
    -d "disable_web_page_preview=1" \
    -d "parse_mode=html" \
    --data-urlencode "text=${text}" \
    -d 'reply_markup={"inline_keyboard":[[{"text":"ᴏʀᴅᴇʀ","url":"https://t.me/TomattoID"}]]}' \
    "${URL}" >/dev/null 2>&1 || true
}

function pasang_ssl() {
  clear
  print_install "Memasang SSL Pada Domain"
  rm -f /etc/xray/xray.key /etc/xray/xray.crt

  domain="$(cat /root/domain 2>/dev/null || true)"
  [ -n "${domain:-}" ] || { print_error "Domain belum ada. Jalankan pasang_domain dulu."; return 1; }

  # ASLI: STOPWEBSERVER=... lalu systemctl stop $STOPWEBSERVER (kalau kosong -> error)
  # FIX :
  STOPWEBSERVER="$(lsof -i:80 2>/dev/null | awk 'NR==2{print $1; exit}')"
  if [ -n "${STOPWEBSERVER:-}" ]; then
    systemctl_try stop "${STOPWEBSERVER}"
  fi
  systemctl_try stop nginx

  rm -rf /root/.acme.sh
  mkdir -p /root/.acme.sh

  curl -fsSL https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
  chmod +x /root/.acme.sh/acme.sh

  /root/.acme.sh/acme.sh --upgrade --auto-upgrade
  /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
  /root/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256
  /root/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc

  # ASLI: chmod 777 /etc/xray/xray.key (bahaya)
  # FIX : kunci 600
  chmod 600 /etc/xray/xray.key
  chmod 644 /etc/xray/xray.crt

  print_success "SSL Certificate"
}

function make_folder_xray() {
  # FIX: hapus semua kemungkinan lokasi db noobz supaya konsisten
  rm -rf /etc/noobz/.noobzvpns.db /etc/noobzvpns/.noobzvpns.db /etc/.noobzvpns.db

  rm -rf /etc/vmess/.vmess.db
  rm -rf /etc/vless/.vless.db
  rm -rf /etc/trojan/.trojan.db
  rm -rf /etc/shadowsocks/.shadowsocks.db
  rm -rf /etc/ssh/.ssh.db
  rm -rf /etc/bot/.bot.db

  mkdir -p /etc/bot /etc/xray /etc/vmess /etc/vless /etc/trojan /etc/shadowsocks /etc/ssh
  mkdir -p /usr/bin/xray/ /var/log/xray/ /var/www/html
  mkdir -p /etc/kyt/limit/{vmess,vless,trojan,ssh}/ip
  mkdir -p /etc/limit/{vmess,vless,trojan,ssh}
  mkdir -p /etc/noobzvpns /etc/limit/noobzvpns/{ip,quota}

  # ASLI: chmod +x /var/log/xray
  # FIX :
  chmod 755 /var/log/xray

  touch /etc/xray/domain /var/log/xray/access.log /var/log/xray/error.log
  touch /etc/vmess/.vmess.db /etc/vless/.vless.db /etc/trojan/.trojan.db /etc/shadowsocks/.shadowsocks.db /etc/ssh/.ssh.db /etc/bot/.bot.db
  touch /etc/.noobzvpns.db
  touch /etc/noobzvpns/.noobzvpns.db

  echo "& plughin Account" >>/etc/vmess/.vmess.db
  echo "& plughin Account" >>/etc/vless/.vless.db
  echo "& plughin Account" >>/etc/trojan/.trojan.db
  echo "& plughin Account" >>/etc/shadowsocks/.shadowsocks.db
  echo "& plughin Account" >>/etc/ssh/.ssh.db
  echo "& plughin Account" >>/etc/noobzvpns/.noobzvpns.db
}

function install_xray() {
  clear
  print_install "Installing Xray Core (Locked v24.12.31) + GeoIP/GeoSite + systemd (clean)"

  XRAY_VERSION="24.12.31"
  ARCH="$(uname -m)"

  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y curl wget unzip ca-certificates >/dev/null 2>&1

  if ! id -u www-data >/dev/null 2>&1; then
    useradd -r -s /usr/sbin/nologin -M www-data
  fi

  local FILE=""
  case "$ARCH" in
    x86_64)  FILE="Xray-linux-64.zip" ;;
    aarch64) FILE="Xray-linux-arm64-v8a.zip" ;;
    *) print_error "Architecture not supported for Xray: $ARCH"; exit 1 ;;
  esac

  install -d -m 755 /etc/xray /usr/local/share/xray /var/log/xray

  local ZIP="/tmp/${FILE}"
  rm -f "$ZIP" /tmp/xray /tmp/geoip.dat /tmp/geosite.dat

  wget -q -O "$ZIP" "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/${FILE}" || {
    print_error "Failed download Xray zip"; exit 1;
  }

  unzip -o "$ZIP" -d /tmp >/dev/null 2>&1
  [ -f /tmp/xray ] || { print_error "Binary xray not found after unzip: ${FILE}"; exit 1; }

  if [ -f /usr/local/bin/xray ]; then
    mv /usr/local/bin/xray "/usr/local/bin/xray.bak.$(date +%s)"
  fi
  install -m 755 /tmp/xray /usr/local/bin/xray

  print_install "Downloading GeoIP & GeoSite"
  wget -q -O /usr/local/share/xray/geoip.dat   "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" || { print_error "Failed download geoip.dat"; exit 1; }
  wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" || { print_error "Failed download geosite.dat"; exit 1; }

  ln -sf /usr/local/share/xray/geoip.dat   /usr/local/bin/geoip.dat
  ln -sf /usr/local/share/xray/geosite.dat /usr/local/bin/geosite.dat
  chmod 644 /usr/local/share/xray/geoip.dat /usr/local/share/xray/geosite.dat /usr/local/bin/geoip.dat /usr/local/bin/geosite.dat

  print_install "Fetching configs"
  wget -q -O /etc/xray/config.json "${REPO}Cfg/config.json" || { print_error "Failed download /etc/xray/config.json"; exit 1; }

  chown -R www-data:www-data /etc/xray /var/log/xray /usr/local/share/xray
  chmod 755 /etc/xray /var/log/xray /usr/local/share/xray
  chmod 644 /etc/xray/config.json

  if [ -f /etc/xray/xray.key ]; then chown www-data:www-data /etc/xray/xray.key; chmod 600 /etc/xray/xray.key; fi
  if [ -f /etc/xray/xray.crt ]; then chown www-data:www-data /etc/xray/xray.crt; chmod 644 /etc/xray/xray.crt; fi

  print_install "Writing systemd unit"
  cat >/etc/systemd/system/xray.service <<'EOF'
[Unit]
Description=Xray Service (Locked v24)
After=network.target nss-lookup.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/etc/xray

CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true

ExecStartPre=/usr/bin/test -r /etc/xray/config.json
ExecStartPre=/usr/bin/test -r /usr/local/bin/geoip.dat
ExecStartPre=/usr/bin/test -r /usr/local/bin/geosite.dat

ExecStartPre=/usr/local/bin/xray run -test -config /etc/xray/config.json
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json

Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload

  runuser -u www-data -- /usr/local/bin/xray run -test -config /etc/xray/config.json >/dev/null 2>&1 || {
    print_error "Xray config test FAILED as www-data. Cek: journalctl -u xray -b --no-pager | tail -200"
    exit 1
  }

  systemctl enable --now xray >/dev/null 2>&1
  systemctl_try restart xray

  systemctl --no-pager -l status xray || true
  print_success "Xray Installed + GeoIP/GeoSite OK + Service OK"
}

function ssh(){
  clear
  print_install "Memasang Password SSH"
  wget -q -O /etc/pam.d/common-password "${REPO}Fls/password"

  # ASLI: chmod +x /etc/pam.d/common-password (file config bukan executable)
  # FIX :
  chmod 644 /etc/pam.d/common-password

  DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration || true

  debconf-set-selections <<<"keyboard-configuration keyboard-configuration/altgr select The default for the keyboard layout"
  debconf-set-selections <<<"keyboard-configuration keyboard-configuration/compose select No compose key"
  debconf-set-selections <<<"keyboard-configuration keyboard-configuration/ctrl_alt_bksp boolean false"
  debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layoutcode string de"
  debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select English"
  debconf-set-selections <<<"keyboard-configuration keyboard-configuration/modelcode string pc105"
  debconf-set-selections <<<"keyboard-configuration keyboard-configuration/model select Generic 105-key (Intl) PC"
  debconf-set-selections <<<"keyboard-configuration keyboard-configuration/optionscode string "
  debconf-set-selections <<<"keyboard-configuration keyboard-configuration/store_defaults_in_debconf_db boolean true"
  debconf-set-selections <<<"keyboard-configuration keyboard-configuration/switch select No temporary switch"
  debconf-set-selections <<<"keyboard-configuration keyboard-configuration/toggle select No toggling"
  debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_layout boolean true"
  debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_options boolean true"
  debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_layout boolean true"
  debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_options boolean true"
  debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variantcode string "
  debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variant select English"
  debconf-set-selections <<<"keyboard-configuration keyboard-configuration/xkb-keymap select "

  cat >/etc/systemd/system/rc-local.service <<'END'
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END

  cat >/etc/rc.local <<'END'
exit 0
END

  chmod +x /etc/rc.local
  systemctl_try enable rc-local
  systemctl_try start rc-local.service

  echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 || true
  sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

  ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
  sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config || true

  print_success "Password SSH"
}

function udp_mini(){
  clear
  print_install "Memasang Service limit Quota"

  # ASLI: wget raw.githubusercontent.com/... (tanpa https -> sering fail)
  # FIX :
  wget -q "https://raw.githubusercontent.com/rwrtx/sctomatto/main/Fls/limit.sh" -O /tmp/limit.sh
  chmod +x /tmp/limit.sh
  /tmp/limit.sh

  wget -q -O /usr/bin/limit-ip "${REPO}Fls/limit-ip"
  chmod +x /usr/bin/limit-ip
  sed -i 's/\r//' /usr/bin/limit-ip

  # ASLI: ProjectAfter=network.target (typo)
  # FIX :
  cat >/etc/systemd/system/vmip.service <<'EOF'
[Unit]
Description=My
After=network.target
[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/limit-ip vmip
Restart=always
[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl_try restart vmip
  systemctl_try enable vmip

  cat >/etc/systemd/system/vlip.service <<'EOF'
[Unit]
Description=My
After=network.target
[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/limit-ip vlip
Restart=always
[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl_try restart vlip
  systemctl_try enable vlip

  cat >/etc/systemd/system/trip.service <<'EOF'
[Unit]
Description=My
After=network.target
[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/limit-ip trip
Restart=always
[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl_try restart trip
  systemctl_try enable trip

  mkdir -p /usr/local/kyt/
  wget -q -O /usr/local/kyt/udp-mini "${REPO}Fls/udp-mini"
  chmod +x /usr/local/kyt/udp-mini

  wget -q -O /etc/systemd/system/udp-mini-1.service "${REPO}Fls/udp-mini-1.service"
  wget -q -O /etc/systemd/system/udp-mini-2.service "${REPO}Fls/udp-mini-2.service"
  wget -q -O /etc/systemd/system/udp-mini-3.service "${REPO}Fls/udp-mini-3.service"

  systemctl_try disable udp-mini-1
  systemctl_try stop udp-mini-1
  systemctl_try enable udp-mini-1
  systemctl_try start udp-mini-1

  systemctl_try disable udp-mini-2
  systemctl_try stop udp-mini-2
  systemctl_try enable udp-mini-2
  systemctl_try start udp-mini-2

  systemctl_try disable udp-mini-3
  systemctl_try stop udp-mini-3
  systemctl_try enable udp-mini-3
  systemctl_try start udp-mini-3

  print_success "files Quota Service"
}

function ssh_slow(){
  clear
  print_install "Memasang modul SlowDNS Server"
  wget -q -O /tmp/nameserver "${REPO}Fls/nameserver"
  chmod +x /tmp/nameserver
  bash /tmp/nameserver | tee /root/install.log
  print_success "SlowDNS"
}

function ins_SSHD(){
  clear
  print_install "Memasang SSHD"
  wget -q -O /etc/ssh/sshd_config "${REPO}Fls/sshd"
  chmod 700 /etc/ssh/sshd_config
  service_try ssh restart
  systemctl_try restart ssh
  print_success "SSHD"
}

function ins_dropbear(){
  clear
  print_install "Menginstall Dropbear"
  apt-get install -y dropbear >/dev/null 2>&1
  wget -q -O /etc/default/dropbear "${REPO}Cfg/dropbear.conf"
  chmod 644 /etc/default/dropbear
  service_try dropbear restart
  print_success "Dropbear"
}

function ins_vnstat(){
  clear
  print_install "Menginstall Vnstat"
  apt-get install -y vnstat libsqlite3-dev >/dev/null 2>&1
  service_try vnstat restart

  wget -q https://humdi.net/vnstat/vnstat-2.6.tar.gz -O /root/vnstat-2.6.tar.gz
  tar zxvf /root/vnstat-2.6.tar.gz >/dev/null 2>&1
  cd /root/vnstat-2.6
  ./configure --prefix=/usr --sysconfdir=/etc
  make
  make install
  cd /root

  vnstat -u -i "$NET" || true
  sed -i "s/Interface \"eth0\"/Interface \"$NET\"/g" /etc/vnstat.conf || true
  chown -R vnstat:vnstat /var/lib/vnstat || true

  systemctl_try enable vnstat
  service_try vnstat restart

  rm -f /root/vnstat-2.6.tar.gz
  rm -rf /root/vnstat-2.6
  print_success "Vnstat"
}

function ins_openvpn(){
  clear
  print_install "Menginstall OpenVPN"
  cd /root
  wget -q "${REPO}Vpn/openvpn" -O /root/openvpn
  chmod +x /root/openvpn
  /root/openvpn
  service_try openvpn restart
  print_success "OpenVPN"
}

function ins_backup(){
  clear
  apt install -y rclone
  printf "q\n" | rclone config || true
  mkdir -p /root/.config/rclone
  wget -q -O /root/.config/rclone/rclone.conf "${REPO}Cfg/rclone.conf"

  cd /bin
  git clone https://github.com/arivpnstores/wondershaper.git
  cd wondershaper
  # ASLI: sudo make install
  # FIX :
  make install
  cd /root
  rm -rf /bin/wondershaper

  : > /home/files
  apt install -y msmtp-mta ca-certificates bsd-mailx

  # CATATAN: ini berisi password plaintext (asli kamu). Lebih aman pakai App Password/env.
  cat<<EOF>>/etc/msmtprc
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
account default
host smtp.gmail.com
port 587
auth on
user oceantestdigital@gmail.com
from oceantestdigital@gmail.com
password jokerman77
logfile ~/.msmtp.log
EOF

  chown -R www-data:www-data /etc/msmtprc || true
  wget -q -O /etc/ipserver "${REPO}Fls/ipserver" && bash /etc/ipserver
}

function ins_swab(){
  clear
  #print_install "Memasang Swap 2 GB"

  gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1 || true)"
  if [ -n "${gotop_latest:-}" ]; then
    gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v${gotop_latest}/gotop_v${gotop_latest}_linux_amd64.deb"
    curl -sL "$gotop_link" -o /tmp/gotop.deb || true
    dpkg -i /tmp/gotop.deb >/dev/null 2>&1 || true
  fi

  dd if=/dev/zero of=/swapfile bs=1M count=2048
  mkswap /swapfile
  chown root:root /swapfile
  chmod 0600 /swapfile
  swapon /swapfile || true
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile swap swap defaults 0 0' >> /etc/fstab

  cmd_try chronyd -q 'server 0.id.pool.ntp.org iburst'
  cmd_try chronyc sourcestats -v
  cmd_try chronyc tracking -v

  cd /root
  wget -q "${REPO}Fls/bbr.sh" -O /root/bbr.sh
  chmod +x /root/bbr.sh
  /root/bbr.sh || true
}

function ins_Fail2ban(){
  clear
  print_install "Menginstall Fail2ban (VPN Safe)"
  apt install -y fail2ban

  echo "Banner /etc/banner.txt" >> /etc/ssh/sshd_config || true
  sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/banner.txt"@g' /etc/default/dropbear || true

  wget -q -O /etc/banner.txt "${REPO}Bnr/banner.txt" || true
  wget -q -O /etc/kyt.txt "${REPO}banner/issue.net" || true

  cat >/etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime  = 1800
findtime = 600
maxretry = 5
ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
backend = systemd
banaction = iptables-multiport

[sshd]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s
maxretry = 5
findtime = 600
bantime  = 3600

[sshd-ddos]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s
maxretry = 10
findtime = 120
bantime  = 3600

[nginx-http-auth]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/error.log
maxretry = 6

[nginx-botsearch]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/access.log
maxretry = 10
findtime = 300
bantime  = 1800

[recidive]
enabled  = true
logpath  = /var/log/fail2ban.log
banaction = iptables-allports[name=recidive]
findtime = 86400
maxretry = 5
bantime  = 604800
EOF

  systemctl_try restart fail2ban
  systemctl_try enable fail2ban
  print_success "Fail2ban VPN-Safe Installed"
}

function ins_epro(){
  clear
  print_install "Menginstall ePro WebSocket Proxy"
  wget -q -O /usr/bin/ws "${REPO}Fls/ws"
  wget -q -O /usr/bin/tun.conf "${REPO}Cfg/tun.conf"
  wget -q -O /etc/systemd/system/ws.service "${REPO}Fls/ws.service"

  chmod +x /usr/bin/ws
  chmod 644 /usr/bin/tun.conf
  chmod 644 /etc/systemd/system/ws.service

  systemctl_try disable ws
  systemctl_try stop ws
  systemctl_try enable ws
  systemctl_try start ws
  systemctl_try restart ws

  wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" || true
  wget -q -O /usr/local/share/xray/geoip.dat   "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" || true

  wget -q -O /usr/sbin/ftvpn "${REPO}Fls/ftvpn" || true
  chmod +x /usr/sbin/ftvpn || true

  # iptables anti bittorrent (tetap)
  iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP || true
  iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP || true
  iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP || true
  iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP || true
  iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP || true
  iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP || true
  iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP || true
  iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP || true
  iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP || true
  iptables -A FORWARD -m string --algo bm --string "announce" -j DROP || true
  iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP || true

  iptables-save > /etc/iptables.up.rules || true
  iptables-restore < /etc/iptables.up.rules || true
  netfilter-persistent save || true
  netfilter-persistent reload || true

  apt autoclean -y >/dev/null 2>&1 || true
  apt autoremove -y >/dev/null 2>&1 || true
  print_success "ePro WebSocket Proxy"
}

function ins_restart(){
  clear
  print_install "Restarting  All Packet"
  service_try nginx restart
  service_try openvpn restart
  service_try ssh restart
  service_try dropbear restart
  service_try fail2ban restart
  service_try vnstat restart
  cmd_try /etc/noobzvpns/noobzvpns restart

  systemctl_try restart haproxy
  service_try cron restart

  systemctl daemon-reload || true
  systemctl_try restart noobzvpns
  systemctl_try start netfilter-persistent

  systemctl_try enable --now nginx
  systemctl_try enable --now xray
  systemctl_try enable --now rc-local
  systemctl_try enable --now dropbear
  systemctl_try enable --now openvpn
  systemctl_try enable --now cron
  systemctl_try enable --now haproxy
  systemctl_try enable --now netfilter-persistent
  systemctl_try enable --now ws
  systemctl_try enable --now fail2ban
  systemctl_try enable --now noobzvpns
  systemctl_try enable --now udp-custom

  history -c || true
  echo "unset HISTFILE" >> /etc/profile || true

  rm -f /root/openvpn /root/key.pem /root/cert.pem || true
  print_success "All Packet"
}

function menu(){
  clear
  print_install "Memasang Menu Packet"
  wget -q "${REPO}menu/menu.zip" -O /tmp/menu.zip
  unzip -o /tmp/menu.zip -d /tmp/menu >/dev/null 2>&1
  chmod +x /tmp/menu/menu/*
  mv /tmp/menu/menu/* /usr/local/sbin
  rm -rf /tmp/menu /tmp/menu.zip
}

function profile(){
  clear
  cat >/root/.profile <<'EOF'
if [ "$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi
mesg n || true
welcome
EOF

  cat >/etc/cron.d/log_clear <<'END'
8 0 * * * root /usr/local/bin/log_clear
END

  cat >/usr/local/bin/log_clear <<'END'
#!/bin/bash
tanggal=$(date +"%m-%d-%Y")
waktu=$(date +"%T")
echo "Sucsesfully clear & restart On $tanggal Time $waktu." >> /root/log-clear.txt
systemctl restart udp-custom.service
END
  chmod +x /usr/local/bin/log_clear

  cat >/etc/cron.d/daily_backup <<'END'
0 23 * * * root /usr/local/bin/daily_backup
END

  cat >/usr/local/bin/daily_backup <<'END'
#!/bin/bash
tanggal=$(date +"%m-%d-%Y")
waktu=$(date +"%T")
echo "Sucsesfully Backup On $tanggal Time $waktu." >> /root/log-backup.txt
/usr/local/sbin/backup -r now
END
  chmod +x /usr/local/bin/daily_backup

  cat >/etc/cron.d/xp_sc <<'END'
5 2 * * * root /usr/local/bin/xp_sc
END

  cat >/usr/local/bin/xp_sc <<'END'
#!/bin/bash
/usr/local/sbin/expsc -r now
END
  chmod +x /usr/local/bin/xp_sc

  cat >/etc/cron.d/xp_all <<'END'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
2 0 * * * root /usr/local/sbin/xp
END

  cat >/etc/cron.d/logclean <<'END'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/10 * * * * root /usr/local/sbin/clearlog
END

  cat >/etc/cron.d/daily_reboot <<'END'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 5 * * * root /sbin/reboot
END

  echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
  echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >>/etc/cron.d/log.xray

  service_try cron restart

  echo "5" >/home/daily_reboot

  cat >/etc/systemd/system/rc-local.service <<'EOF'
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
EOF

  echo "/bin/false" >>/etc/shells
  echo "/usr/sbin/nologin" >>/etc/shells

  cat >/etc/rc.local <<'EOF'
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent
exit 0
EOF
  chmod +x /etc/rc.local

  print_success "Menu Packet"
}

function enable_services(){
  clear
  print_install "Enable Service"

  systemctl daemon-reload || true
  systemctl_try start netfilter-persistent
  systemctl_try enable --now rc-local cron netfilter-persistent

  if nginx -t >/dev/null 2>&1; then
    systemctl_try restart nginx
  else
    print_error "Config nginx invalid"
    exit 1
  fi

  systemctl_try restart xray

  if haproxy -c -f /etc/haproxy/haproxy.cfg >/dev/null 2>&1; then
    systemctl_try restart haproxy
  else
    print_error "Config haproxy invalid"
    exit 1
  fi

  systemctl_try restart noobzvpns
  print_success "Enable Service"
}

# =========================
# 10) STUB fungsi yang dipanggil tapi belum ada (biar script gak stop)
# =========================
password_default(){
  # ASLI: dipanggil tapi tidak ada definisi
  # FIX : stub aman
  print_install "password_default (stub)"
  return 0
}

# =========================
# 11) Install sequence
# =========================
function instal(){
  clear
  first_setup
  nginx_install
  base_package
  make_folder_xray
  pasang_domain
  password_default
  pasang_ssl
  install_xray
  ssh
  udp_mini
  ssh_slow
  ins_SSHD
  ins_dropbear
  ins_vnstat
  ins_openvpn
  ins_backup
  ins_swab
  ins_Fail2ban
  ins_epro
  ins_restart
  menu
  profile
  enable_services
  restart_system
}

instal

echo ""
history -c || true

# ASLI: rm -rf /root/*.sh (bahaya, bisa hapus file lain)
# FIX : hapus file spesifik yang dibuat script ini
rm -rf /root/menu /root/menu.zip /root/cf.sh /root/openvpn /root/bbr.sh /root/noobzvpns.zip 2>/dev/null || true

secs_to_human "$(($(date +%s) - start))"

# ASLI: sudo hostnamectl ...
# FIX :
hostnamectl set-hostname "$username" >/dev/null 2>&1 || true

clear
echo -e ""
echo -e "\e[94;1m╔═════════════════════════════════════════════════╗\e[0m"
echo -e "\e[96;1m          ----[ TomattoVPN TUNNELING ]----         \e[0m"
echo -e "\e[94;1m╚═════════════════════════════════════════════════╝\e[0m"
echo -e "\e[94;1m╔═════════════════════════════════════════════════╗\e[0m"
echo -e "\e[92;1m            ----[ INSTALL SUCCES ]----             \e[0m"
echo -e "\e[94;1m╚═════════════════════════════════════════════════╝\e[0m"
echo -e "\e[94;1m╔═════════════════════════════════════════════════╗\e[0m"
echo -e "\e[92;1m               ----[ INFO PORT ]----               \e[0m"
echo -e "\e[94;1m╚═════════════════════════════════════════════════╝\e[0m"
echo -e ""
echo -e " \e[93;1m•\e[0m WEBSOCKET / WS / NTLS   :  80,8880,8080,2082,2095,2082 "
echo -e " \e[93;1m•\e[0m SSL  / TLS / GRPC /     :  443,8443 "
echo -e " \e[93;1m•\e[0m UDP CUSTOM              :  1-65535 "
echo -e ""
echo -e "\e[94;1m╚═════════════════════════════════════════════════╝\e[0m"
echo ""
sleep 3
read -p "[ Enter ]  TO REBOOT"
reboot
