#!/usr/bin/env bash
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
IFS=$'\n\t'

# =========================
# TRAP: kalau error, tampilkan line & command (biar ketahuan penyebab terminate)
# =========================
trap 'echo -e "\n\033[1;31m[ERROR]\033[0m line $LINENO: $BASH_COMMAND" >&2' ERR

# =========================
# 0) Helper
# =========================
log(){ echo -e "$*"; }
die(){ echo -e "\e[1;31m[ERROR]\e[0m $*" >&2; exit 1; }

soft_run(){ # jangan bikin terminate untuk hal non-kritis
  "$@" || { echo -e "\e[33m[WARN]\e[0m gagal: $*" >&2; return 0; }
}

wait_apt_lock(){
  local locks=(/var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock)
  for _ in {1..60}; do
    local busy=0
    for f in "${locks[@]}"; do
      if fuser "$f" >/dev/null 2>&1; then busy=1; fi
    done
    [ "$busy" -eq 0 ] && return 0
    sleep 2
  done
  die "APT/DPKG lock masih aktif. Tunggu, lalu jalankan lagi."
}

# =========================
# 1) Cek basic
# =========================
[ "${EUID:-$(id -u)}" -eq 0 ] || die "Jalankan sebagai root."

if command -v systemd-detect-virt >/dev/null 2>&1; then
  if [ "$(systemd-detect-virt 2>/dev/null || true)" = "openvz" ]; then
    die "OpenVZ tidak disupport."
  fi
fi

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|aarch64) : ;;
  *) die "Arsitektur tidak disupport: $ARCH" ;;
esac

OS_ID="$(. /etc/os-release && echo "${ID}")"
OS_PRETTY="$(. /etc/os-release && echo "${PRETTY_NAME}")"
case "$OS_ID" in
  ubuntu|debian) : ;;
  *) die "OS tidak disupport: $OS_PRETTY" ;;
esac

# =========================
# 2) Telegram (opsional)
# =========================
TIMES="10"
CHATID="5423129090"          # <-- chat id kamu
KEY="8308467181:AAG_3Ve3XBjr4_rX86gmNcmi9o-WXbVLcqo"  # <-- bot token kamu
URL="https://api.telegram.org/bot${KEY}/sendMessage"

telegram_send(){
  # FIX: kalau kosong -> skip (jangan terminate)
  if [[ -z "${KEY}" || -z "${CHATID}" ]]; then
    echo -e "\e[33m[WARN]\e[0m Telegram KEY/CHATID kosong -> skip notif"
    return 0
  fi
  soft_run curl -s --max-time "${TIMES}" \
    -d "chat_id=${CHATID}" \
    -d "disable_web_page_preview=1" \
    -d "parse_mode=html" \
    --data-urlencode "text=$1" \
    "${URL}" >/dev/null
}

# =========================
# 3) Matikan apt-daily (biar gak ganggu)
# =========================
soft_run systemctl stop  apt-daily.timer apt-daily-upgrade.timer
soft_run systemctl disable apt-daily.timer apt-daily-upgrade.timer
soft_run systemctl stop  apt-daily.service apt-daily-upgrade.service
soft_run systemctl mask  apt-daily.service apt-daily-upgrade.service

wait_apt_lock
soft_run dpkg --configure -a

# =========================
# 4) Update + paket awal (sekali, rapi)
# =========================
apt-get update -y
apt-get upgrade -y

apt-get install -y \
  curl wget unzip zip ca-certificates gnupg lsb-release software-properties-common \
  net-tools iproute2 dnsutils jq \
  git cron lsof screen

# =========================
# 5) Variabel warna (punyamu, dirapihin)
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
NC='\e[0m'
BlueBee="\e[94;1m"
CYAN="\e[96;1m"
COLOR1="\e[92;1m"

print_ok(){ echo -e "${OK} ${BLUE} $1 ${FONT}"; }
print_install(){
  echo -e "${BlueBee}╔════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN} [•]  $1 ${FONT}"
  echo -e "${BlueBee}╚════════════════════════════════════════════════╝${NC}"
  sleep 1
}
print_error(){ echo -e "${ERROR} ${REDBG} $1 ${FONT}"; }
print_success(){
  echo -e "${BlueBee}╔════════════════════════════════════════════════╗${NC}"
  echo -e "${Green}                 INSTALL SUCCESS  ${FONT}"
  echo -e "${BlueBee}╚════════════════════════════════════════════════╝${NC}"
  sleep 1
}

# =========================
# 6) Info awal (FIX: jangan duplikat & jangan pakai var belum ada)
# =========================
NET="$(ip route | awk '/default/ {print $5; exit}')"
today="$(date +%Y-%m-%d)"              # FIX: dipakai duluan, jadi harus di atas
DATE="$(date +%Y-%m-%d)"
TIMEZONE="$(date +%H:%M:%S)"

MYIP="$(curl -fsSL ipv4.icanhazip.com 2>/dev/null || true)"
IP="${MYIP:-unknown}"

REPO="https://raw.githubusercontent.com/rwrtx/sctomatto/main/"
NOOBZJSON="https://raw.githubusercontent.com/rwrtx/noobzvpns/main/"
start="$(date +%s)"

secs_to_human(){
  echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}

clear
echo -e "${BlueBee}╔════════════════════════════════════════════════╗${NC}"
echo -e "\033[96;1m                TomattoVPN TUNNELING               \033[0m"
echo -e "${BlueBee}╚════════════════════════════════════════════════╝${NC}"
echo -e ""
echo -e "\e[94;1m╔═════════════════════════════════════════════════╗$NC"
echo -e "${OK} Architecture: ${Green}${ARCH}${NC}"
echo -e "${OK} OS          : ${Green}${OS_PRETTY}${NC}"
echo -e "${OK} IP          : ${Green}${IP}${NC}"
echo -e "\e[94;1m╚═════════════════════════════════════════════════╝ $NC"
echo -e ""
read -rp "[ Enter ] TO INSTAL....... : " _
sleep 1
clear
# =========================
# 7) License check (opsional, jangan bikin terminate kalau gagal fetch)
# =========================
username="unknown"
exp="unknown"
if curl -fsSL "https://raw.githubusercontent.com/rwrtx/vvipsc/main/izin" >/tmp/izin 2>/dev/null; then
  if grep -q "${MYIP}" /tmp/izin; then
    username="$(awk -v ip="${MYIP}" '$1==ip{print $2}' /tmp/izin | head -n1)"
    exp="$(awk -v ip="${MYIP}" '$1==ip{print $3}' /tmp/izin | head -n1)"
  fi
fi
rm -f /tmp/izin

# =========================
# 8) Setup awal + HAProxy (rapi)
# =========================
first_setup(){
  clear
  print_install "Initial System Setup"
  timedatectl set-timezone Asia/Jakarta || true

  # iptables persistent auto-save
  echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
  echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

  apt-get install -y haproxy
  systemctl enable haproxy
  print_success
}

nginx_install(){
  clear
  print_install "Install Nginx"
  apt-get install -y nginx
  systemctl enable nginx
  print_success
}

base_package(){
  clear
  print_install "Menginstall Paket Yang Dibutuhkan"
  apt-get install -y at zip pwgen openssl netcat socat cron bash-completion figlet \
    ruby ruby-dev rubygems-integration \
    sudo git jq openvpn easy-rsa \
    vnstat netfilter-persistent iptables-persistent \
    ntpdate chrony
  # FIX: service chrony (bukan chronyd) biar gak terminate
  soft_run systemctl enable --now chrony
  soft_run chronyc tracking -v
  soft_run ntpdate pool.ntp.org
  apt-get autoremove -y
  print_success
}

# =========================
# 9) Domain
# =========================
pasang_domain(){
  clear
  echo -e "\e[94;1m╔════════════════════════════════════════════════╗ \e[0m"
  echo -e "                  \e[92;1m DOMAIN MENU \e[0m  "
  echo -e "\e[94;1m╚════════════════════════════════════════════════╝ \e[0m"
  echo -e ""
  echo -e "               \e[1;32m1)\e[0m Input Your Domain"
  echo -e "               \e[1;32m2)\e[0m Random Domain "
  echo -e ""
  read -rp "   Pilih 1-2 (lainnya=Random) : " host

  if [[ "${host}" == "1" ]]; then
    read -rp "   INPUT YOUR DOMAIN : " host1
    echo "${host1}" > /etc/xray/domain
    echo "${host1}" > /root/domain
  elif [[ "${host}" == "2" ]]; then
    wget -q "${REPO}Fls/cf.sh" -O /root/cf.sh
    chmod +x /root/cf.sh
    /root/cf.sh
    rm -f /root/cf.sh
  else
    print_install "Random Subdomain/Domain is Used"
  fi
}

# =========================
# 10) SSL (FIX: jangan systemctl stop nama process random)
# =========================
pasang_ssl(){
  clear
  print_install "Memasang SSL Pada Domain"
  rm -f /etc/xray/xray.key /etc/xray/xray.crt

  local domain
  domain="$(cat /root/domain 2>/dev/null || true)"
  [[ -n "${domain}" ]] || die "Domain kosong. Isi domain dulu."

  # FIX: stop service yang umum pakai port 80
  soft_run systemctl stop nginx
  soft_run systemctl stop apache2
  soft_run systemctl stop haproxy

  rm -rf /root/.acme.sh
  curl -fsSL https://get.acme.sh -o /tmp/acme.sh
  bash /tmp/acme.sh
  ~/.acme.sh/acme.sh --upgrade --auto-upgrade
  ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt

  ~/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256 --ecc
  ~/.acme.sh/acme.sh --installcert -d "${domain}" \
    --fullchainpath /etc/xray/xray.crt \
    --keypath /etc/xray/xray.key \
    --ecc

  # FIX: key jangan 777
  chmod 600 /etc/xray/xray.key
  chmod 644 /etc/xray/xray.crt

  print_success
}

# =========================
# 11) Folder xray (FIX: path noobz)
# =========================
make_folder_xray(){
  clear
  print_install "Membuat direktori xray & database"

  rm -f /etc/vmess/.vmess.db /etc/vless/.vless.db /etc/trojan/.trojan.db /etc/shadowsocks/.shadowsocks.db /etc/ssh/.ssh.db /etc/bot/.bot.db
  rm -f /etc/noobzvpns/.noobzvpns.db  # FIX: path konsisten

  install -d -m 755 /etc/{bot,xray,vmess,vless,trojan,shadowsocks,ssh,noobzvpns}
  install -d -m 755 /usr/bin/xray /var/log/xray /var/www/html
  install -d -m 755 /etc/kyt/limit/{vmess,vless,trojan,ssh}/ip
  install -d -m 755 /etc/limit/{vmess,vless,trojan,ssh}
  install -d -m 755 /etc/limit/noobzvpns/{ip,quota}

  touch /etc/xray/domain
  touch /var/log/xray/access.log /var/log/xray/error.log

  touch /etc/vmess/.vmess.db /etc/vless/.vless.db /etc/trojan/.trojan.db /etc/shadowsocks/.shadowsocks.db /etc/ssh/.ssh.db /etc/bot/.bot.db
  touch /etc/noobzvpns/.noobzvpns.db  # FIX

  echo "& plughin Account" >>/etc/vmess/.vmess.db
  echo "& plughin Account" >>/etc/vless/.vless.db
  echo "& plughin Account" >>/etc/trojan/.trojan.db
  echo "& plughin Account" >>/etc/shadowsocks/.shadowsocks.db
  echo "& plughin Account" >>/etc/ssh/.ssh.db
  echo "& plughin Account" >>/etc/noobzvpns/.noobzvpns.db

  print_success
}

# =========================
# 12) Xray install (punyamu, dirapihin)
# =========================
install_xray(){
  clear
  print_install "Installing Xray Core (Locked v24.12.31) + GeoIP/GeoSite + systemd"

  local XRAY_VERSION="24.12.31"
  local ARCH_FILE=""

  apt-get install -y curl wget unzip ca-certificates

  if ! id -u www-data >/dev/null 2>&1; then
    useradd -r -s /usr/sbin/nologin -M www-data
  fi

  case "$(uname -m)" in
    x86_64)  ARCH_FILE="Xray-linux-64.zip" ;;
    aarch64) ARCH_FILE="Xray-linux-arm64-v8a.zip" ;;
    *) die "Architecture not supported for Xray: $(uname -m)" ;;
  esac

  install -d -m 755 /etc/xray /usr/local/share/xray /var/log/xray

  local ZIP="/tmp/${ARCH_FILE}"
  rm -f "$ZIP" /tmp/xray

  wget -q -O "$ZIP" "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/${ARCH_FILE}"
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
  chmod 644 /usr/local/share/xray/geoip.dat /usr/local/share/xray/geosite.dat
  chmod 644 /usr/local/bin/geoip.dat /usr/local/bin/geosite.dat

  print_install "Fetching configs"
  wget -q -O /etc/xray/config.json "${REPO}Cfg/config.json"

  chown -R www-data:www-data /etc/xray /var/log/xray /usr/local/share/xray
  chmod 755 /etc/xray /var/log/xray /usr/local/share/xray
  chmod 644 /etc/xray/config.json

  if [ -f /etc/xray/xray.key ]; then
    chown www-data:www-data /etc/xray/xray.key
    chmod 600 /etc/xray/xray.key
  fi
  if [ -f /etc/xray/xray.crt ]; then
    chown www-data:www-data /etc/xray/xray.crt
    chmod 644 /etc/xray/xray.crt
  fi

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

  runuser -u www-data -- /usr/local/bin/xray run -test -config /etc/xray/config.json >/dev/null 2>&1 || \
    die "Xray config test FAILED as www-data. Cek: journalctl -u xray -b --no-pager | tail -200"

  systemctl enable --now xray
  systemctl restart xray
  systemctl --no-pager -l status xray || true

  print_success
}

# =========================
# 13) SSH tuning (FIX: dpkg-reconfigure sering bikin hang/terminate -> dibuat soft)
# =========================
ssh(){
  clear
  print_install "Memasang Password SSH"
  wget -q -O /etc/pam.d/common-password "${REPO}Fls/password"

  # ASLI: dpkg-reconfigure keyboard-configuration
  # FIX: dibuat soft supaya gak terminate / gak nunggu input
  soft_run dpkg-reconfigure keyboard-configuration

  ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
  sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config || true

  print_success
}

# =========================
# 14) UDP mini (FIX: URL wget harus pakai https://)
# =========================
udp_mini(){
  clear
  print_install "Memasang Service limit Quota"
  wget -q "https://raw.githubusercontent.com/rwrtx/sctomatto/main/Fls/limit.sh" -O /root/limit.sh
  chmod +x /root/limit.sh
  /root/limit.sh
  rm -f /root/limit.sh

  wget -q -O /usr/bin/limit-ip "${REPO}Fls/limit-ip"
  chmod +x /usr/bin/limit-ip
  sed -i 's/\r//' /usr/bin/limit-ip || true

  cat >/etc/systemd/system/vmip.service <<'EOF'
[Unit]
Description=VMess IP Limit
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
Description=VLess IP Limit
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
Description=Trojan IP Limit
After=network.target
[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/limit-ip trip
Restart=always
[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now vmip vlip trip

  install -d -m 755 /usr/local/kyt/
  wget -q -O /usr/local/kyt/udp-mini "${REPO}Fls/udp-mini"
  chmod +x /usr/local/kyt/udp-mini

  wget -q -O /etc/systemd/system/udp-mini-1.service "${REPO}Fls/udp-mini-1.service"
  wget -q -O /etc/systemd/system/udp-mini-2.service "${REPO}Fls/udp-mini-2.service"
  wget -q -O /etc/systemd/system/udp-mini-3.service "${REPO}Fls/udp-mini-3.service"

  systemctl daemon-reload
  systemctl enable --now udp-mini-1 udp-mini-2 udp-mini-3

  print_success
}

ssh_slow(){
  clear
  print_install "Memasang modul SlowDNS Server"
  wget -q -O /tmp/nameserver "${REPO}Fls/nameserver"
  chmod +x /tmp/nameserver
  bash /tmp/nameserver | tee /root/install.log
  print_success
}

ins_SSHD(){
  clear
  print_install "Memasang SSHD"
  wget -q -O /etc/ssh/sshd_config "${REPO}Fls/sshd"
  chmod 600 /etc/ssh/sshd_config
  systemctl restart ssh
  print_success
}

ins_dropbear(){
  clear
  print_install "Menginstall Dropbear"
  apt-get install -y dropbear
  wget -q -O /etc/default/dropbear "${REPO}Cfg/dropbear.conf"
  systemctl restart dropbear
  print_success
}

ins_vnstat(){
  clear
  print_install "Menginstall Vnstat"
  apt-get install -y vnstat
  systemctl enable --now vnstat

  # Opsional compile 2.6 (kalau gagal, jangan terminate)
  soft_run apt-get install -y build-essential libsqlite3-dev
  soft_run wget -q https://humdi.net/vnstat/vnstat-2.6.tar.gz -O /tmp/vnstat-2.6.tar.gz
  if [ -f /tmp/vnstat-2.6.tar.gz ]; then
    tar zxf /tmp/vnstat-2.6.tar.gz -C /tmp
    if [ -d /tmp/vnstat-2.6 ]; then
      (cd /tmp/vnstat-2.6 && ./configure --prefix=/usr --sysconfdir=/etc && make && make install) || true
    fi
  fi

  vnstat -u -i "${NET}" || true
  sed -i "s/Interface \"eth0\"/Interface \"${NET}\"/g" /etc/vnstat.conf || true
  systemctl restart vnstat || true

  print_success
}

ins_openvpn(){
  clear
  print_install "Menginstall OpenVPN"
  wget -q "${REPO}Vpn/openvpn" -O /root/openvpn
  chmod +x /root/openvpn
  /root/openvpn
  rm -f /root/openvpn
  systemctl restart openvpn || true
  print_success
}

# =========================
# 15) Backup (FIX: jangan hardcode password; pakai env)
# =========================
ins_backup(){
  clear
  print_install "Backup setup (opsional)"
  apt-get install -y rclone msmtp-mta ca-certificates bsd-mailx || true
  printf "q\n" | rclone config >/dev/null 2>&1 || true

  soft_run wget -q -O /root/.config/rclone/rclone.conf "${REPO}Cfg/rclone.conf"

  : "${SMTP_USER:=}"
  : "${SMTP_PASS:=}"
  if [[ -n "${SMTP_USER}" && -n "${SMTP_PASS}" ]]; then
    cat >/etc/msmtprc <<EOF
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
account default
host smtp.gmail.com
port 587
auth on
user ${SMTP_USER}
from ${SMTP_USER}
password ${SMTP_PASS}
logfile /var/log/msmtp.log
EOF
    chmod 600 /etc/msmtprc
  else
    echo -e "\e[33m[WARN]\e[0m SMTP_USER/SMTP_PASS kosong -> skip msmtp config"
  fi

  soft_run wget -q -O /etc/ipserver "${REPO}Fls/ipserver"
  soft_run bash /etc/ipserver

  print_success
}

ins_swab(){
  clear
  print_install "Swap 2 GB + BBR (opsional)"
  if ! swapon --show | grep -q /swapfile; then
    dd if=/dev/zero of=/swapfile bs=1M count=2048
    mkswap /swapfile
    chmod 0600 /swapfile
    swapon /swapfile
    grep -q '^/swapfile' /etc/fstab || echo '/swapfile swap swap defaults 0 0' >> /etc/fstab
  fi

  soft_run wget -q "${REPO}Fls/bbr.sh" -O /root/bbr.sh
  soft_run chmod +x /root/bbr.sh
  soft_run /root/bbr.sh
  rm -f /root/bbr.sh

  print_success
}

ins_Fail2ban(){
  clear
  print_install "Menginstall Fail2ban (VPN Safe)"
  apt-get install -y fail2ban

  # Banner
  grep -q "Banner /etc/banner.txt" /etc/ssh/sshd_config || echo "Banner /etc/banner.txt" >> /etc/ssh/sshd_config
  sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/banner.txt"@g' /etc/default/dropbear || true
  soft_run wget -q -O /etc/banner.txt "${REPO}Bnr/banner.txt"
  soft_run wget -q -O /etc/kyt.txt "${REPO}banner/issue.net"

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

  systemctl enable --now fail2ban
  systemctl restart ssh || true
  systemctl restart dropbear || true

  print_success
}

ins_epro(){
  clear
  print_install "Menginstall ePro WebSocket Proxy"
  wget -q -O /usr/bin/ws "${REPO}Fls/ws"
  wget -q -O /usr/bin/tun.conf "${REPO}Cfg/tun.conf"
  wget -q -O /etc/systemd/system/ws.service "${REPO}Fls/ws.service"
  chmod +x /usr/bin/ws
  chmod 644 /usr/bin/tun.conf

  systemctl daemon-reload
  systemctl enable --now ws

  # iptables block bittorrent
  iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP || true
  iptables-save > /etc/iptables.up.rules

  # ASLI: iptables-restore -t < /etc/iptables.up.rules
  # FIX: iptables-restore tanpa -t (kalau pakai -t sering error & terminate)
  iptables-restore < /etc/iptables.up.rules || true

  netfilter-persistent save || true
  netfilter-persistent reload || true

  apt-get autoremove -y || true
  print_success
}

ins_restart(){
  clear
  print_install "Restarting All Services"
  soft_run systemctl restart nginx
  soft_run systemctl restart openvpn
  soft_run systemctl restart ssh
  soft_run systemctl restart dropbear
  soft_run systemctl restart fail2ban
  soft_run systemctl restart vnstat
  soft_run systemctl restart haproxy
  soft_run systemctl restart cron
  soft_run systemctl restart netfilter-persistent
  soft_run systemctl restart xray
  soft_run systemctl restart ws
  print_success
}

menu(){
  clear
  print_install "Memasang Menu Packet"
  wget -q "${REPO}menu/menu.zip" -O /root/menu.zip
  unzip -o /root/menu.zip -d /root/menu >/dev/null 2>&1
  chmod +x /root/menu/menu/* || true
  mv /root/menu/menu/* /usr/local/sbin/ || true
  rm -rf /root/menu /root/menu.zip
  print_success
}

profile(){
  clear
  print_install "Setting profile & cron"
  cat >/root/.profile <<'EOF'
if [ "$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi
mesg n || true
welcome || true
EOF
  chmod 644 /root/.profile

  echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
  echo "*/1 * * * * root echo -n > /var/log/xray/access.log"  >/etc/cron.d/log.xray
  systemctl restart cron || true
  print_success
}

enable_services(){
  clear
  print_install "Enable Service"
  systemctl daemon-reload

  systemctl enable --now cron netfilter-persistent nginx haproxy xray ws || true
  nginx -t && systemctl restart nginx || print_error "Config nginx invalid"

  if command -v haproxy >/dev/null 2>&1; then
    haproxy -c -f /etc/haproxy/haproxy.cfg && systemctl restart haproxy || print_error "Config haproxy invalid"
  fi

  print_success
}

password_default(){
  # FIX: fungsi ini memang kamu panggil tapi tidak ada definisi di paste.
  # Jadi dibuat optional: kalau ada file di repo, jalan; kalau tidak, skip.
  clear
  print_install "password_default (optional)"
  local tried=0

  for p in "Fls/password_default.sh" "Fls/password-default.sh" "Fls/passwd.sh"; do
    if wget -q --spider "${REPO}${p}"; then
      tried=1
      wget -q -O /root/password_default.sh "${REPO}${p}"
      chmod +x /root/password_default.sh
      /root/password_default.sh || true
      rm -f /root/password_default.sh
      break
    fi
  done

  if [[ "$tried" -eq 0 ]]; then
    echo -e "\e[33m[WARN]\e[0m password_default file tidak ditemukan di repo -> skip"
  fi

  print_success
}

restart_system(){
  local domain
  domain="$(cat /etc/xray/domain 2>/dev/null || echo "-")"

  local text="
<code>────────────────────</code>
<b>⚡AUTOSCRIPT PREMIUM⚡</b>
<code>────────────────────</code>
<code>Owner    :</code><code>${username}</code>
<code>OS LINUX :</code><code>${OS_PRETTY}</code>
<code>Domain   :</code><code>${domain}</code>
<code>IP VPS   :</code><code>${MYIP}</code>
<code>DATE     :</code><code>${DATE}</code>
<code>Time     :</code><code>${TIMEZONE}</code>
<code>Exp Sc.  :</code><code>${exp}</code>
<code>────────────────────</code>
<b> ❖ TomattoVPN  TUNNELING ❖  </b>
<code>────────────────────</code>
<i>Automatic Notifications</i>"

  telegram_send "${text}"
}

# =========================
# MAIN INSTALL
# =========================
instal(){
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

# Cleanup
history -c || true
rm -rf /root/*.zip /root/*.sh /root/LICENSE /root/README.md /root/noobzvpns.zip 2>/dev/null || true
secs_to_human "$(($(date +%s) - start))"

# hostname (optional)
if [[ -n "${username}" && "${username}" != "unknown" ]]; then
  hostnamectl set-hostname "${username}" || true
fi

clear
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
echo -e " \e[93;1m•\e[0m SSL / TLS / GRPC       : 443,8443"
echo -e " \e[93;1m•\e[0m UDP CUSTOM             : 1-65535"
echo -e ""
sleep 2
read -rp "[ Enter ] TO REBOOT: " _
reboot
