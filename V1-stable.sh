#!/usr/bin/env bash
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive

# =========================
# Trap error biar ketahuan baris terminate
# =========================
trap 'echo -e "\n\033[1;31m[ERROR]\033[0m Line ${LINENO}: ${BASH_COMMAND}\n" >&2; exit 1' ERR

# =========================
# Helper (rapi & aman)
# =========================
log(){ echo -e "$*"; }
die(){ echo -e "\e[1;31m[ERROR]\e[0m $*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ensure_user(){
  local u="$1"
  if ! id -u "$u" >/dev/null 2>&1; then
    useradd -r -s /usr/sbin/nologin -M "$u" || true
  fi
}

wait_apt_lock(){
  # fuser ada di psmisc; kalau tidak ada, skip cek lock
  command -v fuser >/dev/null 2>&1 || return 0

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

apt_install(){
  # install paket; kalau gagal karena repo/versi, tampilkan jelas
  apt-get install -y "$@"
}

fetch_local_or_remote(){
  # pakai file lokal kalau ada (Cfg/Fls/Vpn/menu sudah ada), kalau tidak baru wget dari repo
  # usage: fetch_local_or_remote "Cfg/config.json" "/etc/xray/config.json" "${REPO}Cfg/config.json"
  local rel="$1"
  local dest="$2"
  local url="$3"

  install -d -m 755 "$(dirname "$dest")"

  if [ -f "${SCRIPT_DIR}/${rel}" ]; then
    cp -f "${SCRIPT_DIR}/${rel}" "$dest"
  else
    wget -q -O "$dest" "$url"
  fi
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
systemctl stop  apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1 || true
systemctl disable apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1 || true
systemctl stop  apt-daily.service apt-daily-upgrade.service >/dev/null 2>&1 || true
systemctl mask  apt-daily.service apt-daily-upgrade.service >/dev/null 2>&1 || true

wait_apt_lock
dpkg --configure -a >/dev/null 2>&1 || true

# =========================
# 3) Update + paket awal
# =========================
apt-get update -y
apt-get upgrade -y

# paket minimal (tambahkan psmisc biar fuser ada)
apt_install curl wget unzip zip ca-certificates gnupg lsb-release software-properties-common \
  net-tools iproute2 dnsutils jq psmisc lsof

# optional (kalau repo tidak ada, jangan bikin terminate)
apt-get install -y lolcat wondershaper >/dev/null 2>&1 || true

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
# 5) Info awal + Telegram
# =========================
NET="$(ip route | awk '/default/ {print $5; exit}' || true)"
valid="$(date +"%Y-%m-%d")"
TIME="$(date '+%d %b %Y')"
today="$(date -d "0 days" +"%Y-%m-%d")"

# IP (ambil sekali)
MYIP="$(curl -fsSL ipv4.icanhazip.com || true)"
IP="${MYIP}"
export IP

# Telegram (boleh isi manual / via ENV)
: "${TIMES:10}"
: "${CHATID:5423129090}"
: "${KEY:8308467181:AAG_3Ve3XBjr4_rX86gmNcmi9o-WXbVLcqo}"
URL="https://api.telegram.org/bot${KEY}/sendMessage"

clear
echo -e "${BlueBee}╔════════════════════════════════════════════════╗${NC}"
echo -e "\033[96;1m                TomattoVPN TUNNELING               \033[0m"
echo -e "${BlueBee}╚════════════════════════════════════════════════╝${NC}"
echo -e ""

echo -e "\e[94;1m╔═════════════════════════════════════════════════╗$NC"
echo -e "${OK} Architecture: ${green}${ARCH}${NC}"
echo -e "${OK} OS          : ${green}${OS_PRETTY}${NC}"
echo -e "${OK} IP          : ${green}${IP:-unknown}${NC}"
echo -e "\e[94;1m╚═════════════════════════════════════════════════╝ $NC"
echo -e
read -rp "[ Enter ] TO Install: "
clear
# =========================
# Authorization (izin)
# =========================
rm -f /usr/bin/user /usr/bin/e || true

IZIN_URL="https://raw.githubusercontent.com/rwrtx/vvipsc/main/izin"
izin_line="$(curl -fsSL "$IZIN_URL" | awk -v ip="$MYIP" '$1==ip{print; exit}' || true)"

if [ -z "${izin_line}" ]; then
  die "IP ${MYIP} tidak ada di list izin."
fi

username="$(echo "$izin_line" | awk '{print $2}')"
expx="$(echo "$izin_line" | awk '{print $3}')"
Exp1="$(echo "$izin_line" | awk '{print $4}')"

echo "$username" >/usr/bin/user
echo "$expx"     >/usr/bin/e

exp="$(cat /usr/bin/e)"
DATE="$(date +'%Y-%m-%d')"

datediff() {
  local d1 d2
  d1="$(date -d "$1" +%s)"
  d2="$(date -d "$2" +%s)"
  echo -e "$COLOR1 $NC Expiry In   : $(( (d1 - d2) / 86400 )) Days"
}

Info="(${green}Active${NC})"
Error="(${RED}Expired${NC})"
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

print_ok() { echo -e "${OK} ${BLUE} $1 ${FONT}"; }

print_install() {
  echo -e "${BlueBee}╔════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN} [•]  $1 ${FONT}"
  echo -e "${BlueBee}╚════════════════════════════════════════════════╝${NC}"
  sleep 1
}

print_error() { echo -e "${ERROR} ${REDBG} $1 ${FONT}"; }

print_success() {
  echo -e "${BlueBee}╔════════════════════════════════════════════════╗${NC}"
  echo -e "${Green}                 INSTALL SUCCESS  ${FONT}"
  echo -e "${BlueBee}╚════════════════════════════════════════════════╝${NC}"
  sleep 1
}

# =========================
# Init folder xray base (aman)
# =========================
print_install "Membuat direktori xray"
ensure_user www-data
mkdir -p /etc/xray /var/log/xray /var/lib/kyt
curl -fsSL ifconfig.me > /etc/xray/ipvps || true
touch /etc/xray/domain
chown -R www-data:www-data /var/log/xray || true
chmod 755 /var/log/xray
touch /var/log/xray/access.log /var/log/xray/error.log

# RAM usage (inisialisasi dulu biar gak terminate)
mem_used=0
mem_total=0
while IFS=":" read -r a b; do
  case "$a" in
    "MemTotal") ((mem_used+=${b/kB})); mem_total="${b/kB}" ;;
    "Shmem") ((mem_used+=${b/kB})) ;;
    "MemFree"|"Buffers"|"Cached"|"SReclaimable")
      mem_used="$((mem_used-=${b/kB}))"
    ;;
  esac
done < /proc/meminfo

Ram_Usage="$((mem_used / 1024))"
Ram_Total="$((mem_total / 1024))"

export tanggal="$(date -d "0 days" +"%d-%m-%Y - %X")"
export OS_Name="$(grep -w PRETTY_NAME /etc/os-release | head -n1 | cut -d= -f2 | tr -d '"')"
export Kernel="$(uname -r)"
export Arch="$(uname -m)"
export IP="$(curl -fsSL https://ipinfo.io/ip/ || true)"

# =========================
# Functions
# =========================
first_setup(){
  clear
  print_install "Initial System Setup"

  timedatectl set-timezone Asia/Jakarta || true

  echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
  echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

  apt_install software-properties-common curl gnupg lsb-release

  print_install "Installing HAProxy (OS repo)"
  apt_install haproxy
  systemctl enable haproxy || true

  print_success
}

nginx_install(){
  clear
  print_install "Install Nginx"
  apt_install nginx
  print_success
}

base_package(){
  clear
  print_install "Menginstall Packet Yang Dibutuhkan"

  apt_install at zip pwgen openssl netcat socat cron bash-completion figlet sudo git debconf-utils
  apt-get remove --purge -y exim4 ufw firewalld >/dev/null 2>&1 || true

  apt-get dist-upgrade -y

  # chrony kadang servicenya beda (chrony/chronyd) => jangan terminate
  apt_install chrony ntpdate || true
  systemctl enable --now chrony  >/dev/null 2>&1 || true
  systemctl enable --now chronyd >/dev/null 2>&1 || true
  ntpdate pool.ntp.org >/dev/null 2>&1 || true

  # paket super panjang: biarkan gagal minor tidak terminate (karena beda OS repo)
  apt-get install -y speedtest-cli vnstat openvpn easy-rsa iptables iptables-persistent netfilter-persistent \
    htop lsof tar p7zip-full python3-pip screen xz-utils apt-transport-https dnsutils jq \
    build-essential gcc g++ make cmake sed dirmngr rsyslog dos2unix bc \
    libssl-dev libsqlite3-dev libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libselinux1-dev \
    flex bison libevent-dev libnss3-tools libcurl4-nss-dev libxml-parser-perl ruby ruby-dev rubygems-integration shc \
    msmtp-mta ca-certificates bsd-mailx >/dev/null 2>&1 || true

  apt-get clean -y >/dev/null 2>&1 || true
  apt-get autoremove -y >/dev/null 2>&1 || true

  print_success
}

pasang_domain(){
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
  read -rp "   Please select numbers 1-2 or Any Button(Random) : " host
  echo ""

  if [[ "${host}" == "1" ]]; then
    clear
    read -rp "   INPUT YOUR DOMAIN : " host1
    echo "IP=" >> /var/lib/kyt/ipvps.conf
    echo "$host1" > /etc/xray/domain
    echo "$host1" > /root/domain

  elif [[ "${host}" == "2" ]]; then
    # kalau punya lokal Fls/cf.sh, pakai lokal
    if [ -f "${SCRIPT_DIR}/Fls/cf.sh" ]; then
      chmod +x "${SCRIPT_DIR}/Fls/cf.sh"
      bash "${SCRIPT_DIR}/Fls/cf.sh"
    else
      wget -q -O /root/cf.sh "${REPO}Fls/cf.sh"
      chmod +x /root/cf.sh
      bash /root/cf.sh
      rm -f /root/cf.sh
    fi
  else
    print_install "Random Subdomain/Domain is Used"
  fi
}

# INFO ISP VPS (fix syntax error CITY extra ')')
ISP="$(cat /etc/xray/isp 2>/dev/null || true)"
CITY="$(cat /etc/xray/city 2>/dev/null || true)"
IPVPS="$(curl -fsSL ipv4.icanhazip.com || true)"
domain="$(cat /etc/xray/domain 2>/dev/null || true)"
MODEL="$(grep -w PRETTY_NAME /etc/os-release | head -n1 | cut -d= -f2 | tr -d '"')"
TIMEZONE="$(date +%H:%M:%S)"
DATEVPS="$(date +'%d/%m/%Y')"

restart_system(){
  # Telegram notify: kalau CHATID/KEY kosong => skip biar gak terminate
  if [[ -z "${CHATID}" || -z "${KEY}" ]]; then
    return 0
  fi

  local TEXT
  TEXT="
<code>────────────────────</code>
<b>⚡AUTOSCRIPT PREMIUM⚡</b>
<code>────────────────────</code>
<code>Owner    :</code><code>${username}</code>
<code>OS LINUX :</code><code>${MODEL}</code>
<code>Domain   :</code><code>${domain}</code>
<code>IP VPS   :</code><code>${MYIP}</code>
<code>DATE     :</code><code>${DATE}</code>
<code>Time     :</code><code>${TIMEZONE}</code>
<code>Exp Sc.  :</code><code>${exp}</code>
<code>────────────────────</code>
<b> ❖ TomattoVPN  TUNNELING ❖  </b>
<code>────────────────────</code>
<i>Automatic Notifications</i>
"

  curl -s --max-time "${TIMES}" \
    -d "chat_id=${CHATID}" \
    -d "disable_web_page_preview=1" \
    --data-urlencode "text=${TEXT}" \
    -d "parse_mode=html" \
    "${URL}" >/dev/null 2>&1 || true
}

pasang_ssl(){
  clear
  print_install "Memasang SSL Pada Domain"

  rm -f /etc/xray/xray.key /etc/xray/xray.crt || true
  domain="$(cat /root/domain 2>/dev/null || true)"
  [ -n "$domain" ] || die "Domain belum di set. Jalankan pasang_domain dulu."

  # stop process yang pakai port 80 (aman)
  local pids
  pids="$(lsof -tiTCP:80 -sTCP:LISTEN 2>/dev/null || true)"
  if [ -n "$pids" ]; then
    kill -TERM $pids >/dev/null 2>&1 || true
    sleep 2
  fi

  systemctl stop nginx >/dev/null 2>&1 || true

  rm -rf /root/.acme.sh
  mkdir -p /root/.acme.sh

  curl -fsSL https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
  chmod +x /root/.acme.sh/acme.sh

  /root/.acme.sh/acme.sh --upgrade --auto-upgrade
  /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
  /root/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256
  /root/.acme.sh/acme.sh --installcert -d "$domain" \
    --fullchainpath /etc/xray/xray.crt \
    --keypath /etc/xray/xray.key --ecc

  chmod 600 /etc/xray/xray.key
  chmod 644 /etc/xray/xray.crt

  print_success
}

make_folder_xray(){
  print_install "Membuat folder database & limit"
  rm -f /etc/vmess/.vmess.db /etc/vless/.vless.db /etc/trojan/.trojan.db /etc/shadowsocks/.shadowsocks.db \
        /etc/ssh/.ssh.db /etc/bot/.bot.db /etc/noobzvpns/.noobzvpns.db >/dev/null 2>&1 || true

  mkdir -p /etc/{bot,xray,vmess,vless,trojan,shadowsocks,ssh,noobzvpns} \
           /usr/bin/xray /var/log/xray /var/www/html \
           /etc/kyt/limit/{vmess,vless,trojan,ssh}/ip \
           /etc/limit/{vmess,vless,trojan,ssh} \
           /etc/limit/noobzvpns/{ip,quota}

  chmod 755 /var/log/xray
  touch /etc/xray/domain /var/log/xray/access.log /var/log/xray/error.log
  touch /etc/vmess/.vmess.db /etc/vless/.vless.db /etc/trojan/.trojan.db /etc/shadowsocks/.shadowsocks.db
  touch /etc/ssh/.ssh.db /etc/bot/.bot.db /etc/noobzvpns/.noobzvpns.db

  echo "& plughin Account" >>/etc/vmess/.vmess.db
  echo "& plughin Account" >>/etc/vless/.vless.db
  echo "& plughin Account" >>/etc/trojan/.trojan.db
  echo "& plughin Account" >>/etc/shadowsocks/.shadowsocks.db
  echo "& plughin Account" >>/etc/ssh/.ssh.db
  echo "& plughin Account" >>/etc/noobzvpns/.noobzvpns.db
}

install_xray(){
  clear
  print_install "Installing Xray Core (Locked v24.12.31) + GeoIP/GeoSite + systemd (clean)"

  local XRAY_VERSION="24.12.31"
  local ARCHI
  ARCHI="$(uname -m)"

  apt_install curl wget unzip ca-certificates

  ensure_user www-data

  local FILE=""
  case "$ARCHI" in
    x86_64)  FILE="Xray-linux-64.zip" ;;
    aarch64) FILE="Xray-linux-arm64-v8a.zip" ;;
    *) print_error "Architecture not supported for Xray: $ARCHI"; exit 1 ;;
  esac

  install -d -m 755 /etc/xray /usr/local/share/xray /var/log/xray

  local ZIP="/tmp/${FILE}"
  rm -f "$ZIP" /tmp/xray

  wget -q -O "$ZIP" "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/${FILE}"
  unzip -o "$ZIP" -d /tmp >/dev/null 2>&1
  [ -f /tmp/xray ] || die "Binary xray tidak ditemukan setelah unzip."

  if [ -f /usr/local/bin/xray ]; then
    mv /usr/local/bin/xray "/usr/local/bin/xray.bak.$(date +%s)"
  fi
  install -m 755 /tmp/xray /usr/local/bin/xray

  print_install "Downloading GeoIP & GeoSite"
  wget -q -O /usr/local/share/xray/geoip.dat   "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
  wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
  ln -sf /usr/local/share/xray/geoip.dat   /usr/local/bin/geoip.dat
  ln -sf /usr/local/share/xray/geosite.dat /usr/local/bin/geosite.dat
  chmod 644 /usr/local/share/xray/geoip.dat /usr/local/share/xray/geosite.dat /usr/local/bin/geoip.dat /usr/local/bin/geosite.dat

  print_install "Fetching configs"
  fetch_local_or_remote "Cfg/config.json" "/etc/xray/config.json" "${REPO}Cfg/config.json"

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
    die "Xray config test FAILED as www-data. Cek: journalctl -u xray -b --no-pager | tail -200"
  }

  systemctl enable --now xray >/dev/null 2>&1
  systemctl restart xray

  systemctl --no-pager -l status xray || true
  print_success
}

ssh(){
  clear
  print_install "Memasang Password SSH"

  fetch_local_or_remote "Fls/password" "/etc/pam.d/common-password" "${REPO}Fls/password"
  chmod 644 /etc/pam.d/common-password

  # keyboard reconfigure kadang bikin prompt / error -> jangan terminate
  DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration >/dev/null 2>&1 || true

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
#!/bin/bash
exit 0
END
  chmod +x /etc/rc.local

  systemctl enable --now rc-local.service >/dev/null 2>&1 || true

  echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 || true
  grep -q "disable_ipv6" /etc/rc.local || echo "echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6" >> /etc/rc.local

  ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
  sed -i 's/^AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config 2>/dev/null || true

  print_success
}

udp_mini(){
  clear
  print_install "Memasang Service limit Quota"

  # FIX: url wajib pakai https://
  wget -q -O /tmp/limit.sh "https://raw.githubusercontent.com/rwrtx/sctomatto/main/Fls/limit.sh"
  chmod +x /tmp/limit.sh
  bash /tmp/limit.sh

  fetch_local_or_remote "Fls/limit-ip" "/usr/bin/limit-ip" "${REPO}Fls/limit-ip"
  chmod +x /usr/bin/limit-ip
  sed -i 's/\r//' /usr/bin/limit-ip || true

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
  systemctl enable --now vmip vlip trip >/dev/null 2>&1 || true

  mkdir -p /usr/local/kyt
  fetch_local_or_remote "Fls/udp-mini" "/usr/local/kyt/udp-mini" "${REPO}Fls/udp-mini"
  chmod +x /usr/local/kyt/udp-mini

  fetch_local_or_remote "Fls/udp-mini-1.service" "/etc/systemd/system/udp-mini-1.service" "${REPO}Fls/udp-mini-1.service"
  fetch_local_or_remote "Fls/udp-mini-2.service" "/etc/systemd/system/udp-mini-2.service" "${REPO}Fls/udp-mini-2.service"
  fetch_local_or_remote "Fls/udp-mini-3.service" "/etc/systemd/system/udp-mini-3.service" "${REPO}Fls/udp-mini-3.service"

  systemctl daemon-reload
  systemctl enable --now udp-mini-1 udp-mini-2 udp-mini-3 >/dev/null 2>&1 || true

  print_success
}

ssh_slow(){
  clear
  print_install "Memasang modul SlowDNS Server"
  fetch_local_or_remote "Fls/nameserver" "/tmp/nameserver" "${REPO}Fls/nameserver"
  chmod +x /tmp/nameserver
  bash /tmp/nameserver | tee /root/install.log
  print_success
}

ins_SSHD(){
  clear
  print_install "Memasang SSHD"
  fetch_local_or_remote "Fls/sshd" "/etc/ssh/sshd_config" "${REPO}Fls/sshd"
  chmod 600 /etc/ssh/sshd_config
  systemctl restart ssh || /etc/init.d/ssh restart || true
  print_success
}

ins_dropbear(){
  clear
  print_install "Menginstall Dropbear"
  apt_install dropbear
  fetch_local_or_remote "Cfg/dropbear.conf" "/etc/default/dropbear" "${REPO}Cfg/dropbear.conf"
  chmod 644 /etc/default/dropbear
  systemctl restart dropbear || /etc/init.d/dropbear restart || true
  print_success
}

ins_vnstat(){
  clear
  print_install "Menginstall Vnstat"
  apt_install vnstat
  systemctl enable --now vnstat >/dev/null 2>&1 || true

  if [ -n "${NET:-}" ]; then
    vnstat -u -i "$NET" >/dev/null 2>&1 || true
    sed -i "s/^Interface \".*\"/Interface \"${NET}\"/g" /etc/vnstat.conf 2>/dev/null || true
  fi

  systemctl restart vnstat >/dev/null 2>&1 || true
  print_success
}

ins_openvpn(){
  clear
  print_install "Menginstall OpenVPN"
  # pakai lokal kalau ada
  if [ -f "${SCRIPT_DIR}/Vpn/openvpn" ]; then
    chmod +x "${SCRIPT_DIR}/Vpn/openvpn"
    bash "${SCRIPT_DIR}/Vpn/openvpn"
  else
    wget -q -O /root/openvpn "${REPO}Vpn/openvpn"
    chmod +x /root/openvpn
    bash /root/openvpn
  fi
  systemctl restart openvpn >/dev/null 2>&1 || /etc/init.d/openvpn restart || true
  print_success
}

ins_backup(){
  clear
  print_install "Backup dependencies"
  apt-get install -y rclone >/dev/null 2>&1 || true
  print_success
}

ins_swab(){
  clear
  print_install "Swap 2GB + BBR (optional)"
  dd if=/dev/zero of=/swapfile bs=1M count=2048 >/dev/null 2>&1 || true
  mkswap /swapfile >/dev/null 2>&1 || true
  chmod 0600 /swapfile || true
  swapon /swapfile >/dev/null 2>&1 || true
  grep -q '^/swapfile' /etc/fstab || echo "/swapfile swap swap defaults 0 0" >> /etc/fstab
  # bbr optional
  if [ -f "${SCRIPT_DIR}/Fls/bbr.sh" ]; then
    chmod +x "${SCRIPT_DIR}/Fls/bbr.sh"
    bash "${SCRIPT_DIR}/Fls/bbr.sh" || true
  else
    wget -q -O /tmp/bbr.sh "${REPO}Fls/bbr.sh" && chmod +x /tmp/bbr.sh && bash /tmp/bbr.sh || true
  fi
  print_success
}

ins_Fail2ban(){
  clear
  print_install "Menginstall Fail2ban (VPN Safe)"
  apt_install fail2ban

  # banner optional
  if [ -f "${SCRIPT_DIR}/Bnr/banner.txt" ]; then
    cp -f "${SCRIPT_DIR}/Bnr/banner.txt" /etc/banner.txt
  else
    wget -q -O /etc/banner.txt "${REPO}Bnr/banner.txt" || true
  fi

  echo "Banner /etc/banner.txt" >> /etc/ssh/sshd_config 2>/dev/null || true

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
maxretry = 5
findtime = 600
bantime  = 3600

[sshd-ddos]
enabled  = true
port     = ssh
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

  systemctl enable --now fail2ban >/dev/null 2>&1 || true
  print_success
}

ins_epro(){
  clear
  print_install "Menginstall ePro WebSocket Proxy"
  fetch_local_or_remote "Fls/ws" "/usr/bin/ws" "${REPO}Fls/ws"
  fetch_local_or_remote "Cfg/tun.conf" "/usr/bin/tun.conf" "${REPO}Cfg/tun.conf"
  fetch_local_or_remote "Fls/ws.service" "/etc/systemd/system/ws.service" "${REPO}Fls/ws.service"
  chmod +x /usr/bin/ws
  chmod 644 /usr/bin/tun.conf
  systemctl daemon-reload
  systemctl enable --now ws >/dev/null 2>&1 || true
  print_success
}

ins_restart(){
  clear
  print_install "Restarting All Packet"
  systemctl restart nginx  >/dev/null 2>&1 || true
  systemctl restart openvpn >/dev/null 2>&1 || true
  systemctl restart ssh >/dev/null 2>&1 || true
  systemctl restart dropbear >/dev/null 2>&1 || true
  systemctl restart fail2ban >/dev/null 2>&1 || true
  systemctl restart vnstat >/dev/null 2>&1 || true
  systemctl restart haproxy >/dev/null 2>&1 || true
  systemctl restart cron >/dev/null 2>&1 || true
  systemctl restart xray >/dev/null 2>&1 || true
  systemctl start netfilter-persistent >/dev/null 2>&1 || true
  print_success
}

menu(){
  clear
  print_install "Memasang Menu Packet"
  if [ -d "${SCRIPT_DIR}/menu" ]; then
    chmod +x "${SCRIPT_DIR}/menu/"* || true
    install -m 755 "${SCRIPT_DIR}/menu/"* /usr/local/sbin/ || true
  else
    wget -q -O /tmp/menu.zip "${REPO}menu/menu.zip"
    unzip -o /tmp/menu.zip -d /tmp/menu >/dev/null 2>&1
    chmod +x /tmp/menu/menu/* || true
    mv /tmp/menu/menu/* /usr/local/sbin/ || true
    rm -rf /tmp/menu /tmp/menu.zip
  fi
  print_success
}

profile(){
  clear
  print_install "Setup Profile & Cron"

  cat >/root/.profile <<'EOF'
if [ "$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi
mesg n || true
command -v welcome >/dev/null 2>&1 && welcome || true
EOF

  # cron file minimal (rapih)
  echo "*/1 * * * * root : > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
  echo "*/1 * * * * root : > /var/log/xray/access.log"  >/etc/cron.d/log.xray
  systemctl restart cron >/dev/null 2>&1 || true

  print_success
}

enable_services(){
  clear
  print_install "Enable Service"
  systemctl daemon-reload

  systemctl enable --now rc-local cron netfilter-persistent >/dev/null 2>&1 || true

  nginx -t >/dev/null 2>&1 && systemctl restart nginx || true
  haproxy -c -f /etc/haproxy/haproxy.cfg >/dev/null 2>&1 && systemctl restart haproxy || true
  systemctl restart xray >/dev/null 2>&1 || true

  print_success
}

# optional function (asli kamu ada di script lain, biar gak terminate kalau belum ada)
password_default(){
  # kalau kamu punya versi aslinya, taruh di sini.
  # untuk sekarang: tidak bikin terminate.
  return 0
}

instal(){
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

# =========================
# RUN
# =========================
instal

# summary
secs_to_human "$(($(date +%s) - start))"

# hostname aman
if [ -n "${username:-}" ]; then
  hostnamectl set-hostname "$username" >/dev/null 2>&1 || true
fi

clear
echo -e ""
echo -e "\e[94;1m╔═════════════════════════════════════════════════╗\e[0m"
echo -e "\e[96;1m          ----[ TomattoVPN TUNNELING ]----         \e[0m"
echo -e "\e[94;1m╚═════════════════════════════════════════════════╝\e[0m"
echo -e "\e[94;1m╔═════════════════════════════════════════════════╗\e[0m"
echo -e "\e[92;1m            ----[ INSTALL SUCCESS ]----            \e[0m"
echo -e "\e[94;1m╚═════════════════════════════════════════════════╝\e[0m"
echo -e "\e[94;1m╔═════════════════════════════════════════════════╗\e[0m"
echo -e "\e[92;1m               ----[ INFO PORT ]----               \e[0m"
echo -e "\e[94;1m╚═════════════════════════════════════════════════╝\e[0m"
echo -e ""
echo -e " \e[93;1m•\e[0m WEBSOCKET / WS / NTLS   : 80,8880,8080,2082,2095"
echo -e " \e[93;1m•\e[0m SSL / TLS / GRPC        : 443,8443"
echo -e " \e[93;1m•\e[0m UDP CUSTOM              : 1-65535"
echo -e ""
echo -e "\e[94;1m╚═════════════════════════════════════════════════╝\e[0m"
echo ""

sleep 3
read -rp "[ Enter ] TO REBOOT: "
reboot
