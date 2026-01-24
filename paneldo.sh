#!/bin/bash
systemctl stop apt-daily.service apt-daily-upgrade.service >/dev/null 2>&1
systemctl disable apt-daily.service apt-daily-upgrade.service >/dev/null 2>&1
sleep 2
dpkg --configure -a >/dev/null 2>&1
apt update -y
apt upgrade -y
apt install lolcat -y
apt install curl -y
apt install wondershaper -y
gem install lolcat
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
NET=$(ip route | awk '/default/ {print $5; exit}')
valid=$(date +"%Y-%m-%d")
password_default(){ :; }
TIME=$(date '+%d %b %Y')
ipsaya=$(wget -qO- ipinfo.io/ip)
TIMES="10"
CHATID=""
KEY=""
URL="https://api.telegram.org/bot$KEY/sendMessage"
clear
export IP=$( curl -sS icanhazip.com )
clear
clear && clear && clear
clear;clear;clear
echo -e "${BlueBee}╔════════════════════════════════════════════════╗${NC}"
echo -e "\033[96;1m                TomattoVPN TUNNELING               \033[0m"
echo -e "${BlueBee}╚════════════════════════════════════════════════╝${NC}"
echo ""
if [[ $( uname -m | awk '{print $1}' ) == "x86_64" ]]; then
echo -e "\e[94;1m╔═════════════════════════════════════════════════╗$NC"
echo -e "${OK} Your Architecture Is Supported ( ${green}$( uname -m )${NC} )"
echo -e "\e[94;1m╚═════════════════════════════════════════════════╝ $NC"
echo -e ""
else
echo -e "\e[94;1m╔═════════════════════════════════════════════════╗$NC"
echo -e "${EROR} Your Architecture Is Not Supported ( ${YELLOW}$( uname -m )${NC} )"
echo -e "\e[94;1m╚═════════════════════════════════════════════════╝ $NC"
exit 1
fi
if [[ $( cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g' ) == "ubuntu" ]]; then
echo -e "\e[94;1m╔═════════════════════════════════════════════════╗$NC"
echo -e "${OK} Your OS Is Supported ( ${green}$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g' )${NC} )"
echo -e "\e[94;1m╚═════════════════════════════════════════════════╝ $NC"
elif [[ $( cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g' ) == "debian" ]]; then
echo -e "\e[94;1m╔═════════════════════════════════════════════════╗$NC"
echo -e "${OK} Your OS Is Supported ( ${green}$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g' )${NC} )"
echo -e "\e[94;1m╚═════════════════════════════════════════════════╝ $NC"
else
echo -e "\e[94;1m╔═════════════════════════════════════════════════╗$NC"
echo -e "${EROR} Your OS Is Not Supported ( ${YELLOW}$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g' )${NC} )"
echo -e "\e[94;1m╚═════════════════════════════════════════════════╝ $NC"
exit 1
fi
if [[ $ipsaya == "" ]]; then
echo -e "\e[94;1m╔═════════════════════════════════════════════════╗$NC"
echo -e "${EROR} IP Address ( ${RED}Not Detected${NC} )"
echo -e "\e[94;1m╚═════════════════════════════════════════════════╝ $NC"
else
echo -e "\e[94;1m╔═════════════════════════════════════════════════╗$NC"
echo -e "${OK} IP Address ( ${green}$IP${NC} )"
echo -e "\e[94;1m╚═════════════════════════════════════════════════╝ $NC"
fi
echo ""
echo ""
read -p "$( echo -e "${GRAY}[${NC}${green}ENTER${NC}${GRAY}]${NC} For Starting Installation") "
echo ""
clear
echo ""
echo -e " _____ _   _ _   _ _   _ _____ _     ___ _   _  ____ " | lolcat
echo -e "|_   _| | | | \ | | \ | | ____| |   |_ _| \ | |/ ___| " | lolcat
echo -e "  | | | | | |  \| |  \| |  _| | |    | ||  \| | |  _ " | lolcat
echo -e "  | | | |_| | |\  | |\  | |___| |___ | || |\  | |_| | " | lolcat
echo -e "  |_|  \___/|_| \_|_| \_|_____|_____|___|_| \_|\____| " | lolcat
echo ""
echo -e "\e[32mPlease Wait...............!!!!!!\e[0m"
echo ""
sleep 3
clear
if [ "${EUID}" -ne 0 ]; then
echo "You need to run this script as root"
exit 1
fi
if [ "$(systemd-detect-virt)" == "openvz" ]; then
echo "OpenVZ is not supported"
exit 1
fi
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'
MYIP=$(curl -sS ipv4.icanhazip.com)
echo -e "\e[32mloading...\e[0m"
clear
MYIP=$(curl -sS ipv4.icanhazip.com)
echo -e "\e[32mloading...\e[0m"
clear
clear
rm -f /usr/bin/user
username=$(curl https://raw.githubusercontent.com/rwrtx/vvipsc/main/izin | grep $MYIP | awk '{print $2}')
echo "$username" >/usr/bin/user
expx=$(curl https://raw.githubusercontent.com/rwrtx/vvipsc/main/izin | grep $MYIP | awk '{print $3}')
echo "$expx" >/usr/bin/e
username=$(cat /usr/bin/user)
oid=$(cat /usr/bin/ver)
exp=$(cat /usr/bin/e)
clear
d1=$(date -d "$valid" +%s)
d2=$(date -d "$today" +%s)
certifacate=$(((d1 - d2) / 86400))
DATE=$(date +'%Y-%m-%d')
datediff() {
d1=$(date -d "$1" +%s)
d2=$(date -d "$2" +%s)
echo -e "$COLOR1 $NC Expiry In   : $(( (d1 - d2) / 86400 )) Days"
}
mai="datediff "$Exp" "$DATE""
Info="(${green}Active${NC})"
Error="(${RED}ExpiRED${NC})"
today=`date -d "0 days" +"%Y-%m-%d"`
Exp1=$(curl https://raw.githubusercontent.com/rwrtx/vvipsc/main/izin | grep $MYIP | awk '{print $4}')
if [[ $today < $Exp1 ]]; then
sts="${Info}"
else
sts="${Error}"
fi
echo -e "\e[32mloading...\e[0m"
clear
REPO="https://raw.githubusercontent.com/rwrtx/sctomatto/main/"
NOOBZJSON="https://raw.githubusercontent.com/rwrtx/noobzvpns/main/"
start=$(date +%s)
secs_to_human() {
echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}
function print_ok() {
echo -e "${OK} ${BLUE} $1 ${FONT}"
}
function print_install() {
echo -e "${BlueBee}╔════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN} [•]  $1 ${FONT}"
echo -e "${BlueBee}╚════════════════════════════════════════════════╝${NC}"
sleep 1
}
function print_error() {
echo -e "${ERROR} ${REDBG} $1 ${FONT}"
}
function print_success() {
if [[ 0 -eq $? ]]; then
echo -e "${BlueBee}╔════════════════════════════════════════════════╗${NC}"
echo -e "${Green}                 INSTALL SUCCESS  ${FONT}"
echo -e "${BlueBee}╚════════════════════════════════════════════════╝${NC}"
sleep 2
fi
}
function is_root() {
if [[ 0 == "$UID" ]]; then
print_ok "Root user Start installation process"
else
print_error "The current user is not the root user, please switch to the root user and run the script again"
fi
}
print_install "Membuat direktori xray"
mkdir -p /etc/xray
curl -s ifconfig.me > /etc/xray/ipvps
touch /etc/xray/domain
mkdir -p /var/log/xray
chown www-data.www-data /var/log/xray
chmod +x /var/log/xray
touch /var/log/xray/access.log
touch /var/log/xray/error.log
mkdir -p /var/lib/kyt >/dev/null 2>&1
while IFS=":" read -r a b; do
case $a in
"MemTotal") ((mem_used+=${b/kB})); mem_total="${b/kB}" ;;
"Shmem") ((mem_used+=${b/kB}))  ;;
"MemFree" | "Buffers" | "Cached" | "SReclaimable")
mem_used="$((mem_used-=${b/kB}))"
;;
esac
done < /proc/meminfo
Ram_Usage="$((mem_used / 1024))"
Ram_Total="$((mem_total / 1024))"
export tanggal=`date -d "0 days" +"%d-%m-%Y - %X" `
export OS_Name=$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/PRETTY_NAME//g' | sed 's/=//g' | sed 's/"//g' )
export Kernel=$( uname -r )
export Arch=$( uname -m )
export IP=$( curl -s https://ipinfo.io/ip/ )
function first_setup(){
  clear
  print_install "Initial System Setup"

  # Timezone
  timedatectl set-timezone Asia/Jakarta

  # Iptables persistent auto-save
  echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
  echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

  # Deteksi OS
  OS_ID=$(grep -w ID /etc/os-release | head -n1 | cut -d= -f2 | tr -d '"')
  OS_NAME=$(grep -w PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')

  echo "Setup dependencies for $OS_NAME"

  # Paket dasar yang dibutuhkan haproxy & repo
  apt install -y software-properties-common curl gnupg lsb-release

  # ==============================
  # INSTALL HAPROXY (CLEAN WAY)
  # ==============================
  echo "Installing HAProxy from official OS repository"
  apt install -y haproxy

  # Enable haproxy service
  systemctl enable haproxy

  print_success "Base system & HAProxy installed"
}

clear
function nginx_install() {
if [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "ubuntu" ]]; then
print_install "Setup nginx For OS Is $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
sudo apt-get install nginx -y
elif [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "debian" ]]; then
print_success "Setup nginx For OS Is $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
apt -y install nginx
else
echo -e " Your OS Is Not Supported ( ${YELLOW}$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')${FONT} )"
fi
}
function base_package() {
clear
print_install "Menginstall Packet Yang Dibutuhkan"
apt install at -y
apt install zip pwgen openssl netcat socat cron bash-completion -y
apt install figlet -y
apt dist-upgrade -y
systemctl enable chronyd
systemctl restart chronyd
systemctl enable chrony
systemctl restart chrony
chronyc sourcestats -v
chronyc tracking -v
apt install ntpdate -y
ntpdate pool.ntp.org
apt install sudo -y
sudo apt-get clean all
sudo apt-get autoremove -y
sudo apt-get install -y debconf-utils
sudo apt-get remove --purge exim4 -y
sudo apt-get remove --purge ufw firewalld -y
sudo apt-get install -y --no-install-recommends software-properties-common
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
sudo apt-get install -y speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools libevent-dev bc rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev sed dirmngr libxml-parser-perl build-essential gcc g++ python htop lsof tar wget curl ruby zip unzip p7zip-full python3-pip libc6 util-linux build-essential msmtp-mta ca-certificates bsd-mailx iptables iptables-persistent netfilter-persistent net-tools openssl ca-certificates gnupg gnupg2 ca-certificates lsb-release gcc shc make cmake git screen socat xz-utils apt-transport-https gnupg1 dnsutils cron bash-completion ntpdate chrony jq openvpn easy-rsa
print_success "Packet Yang Dibutuhkan"
}
clear
function pasang_domain() {
echo -e ""
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
echo
read -p "   Please select numbers 1-2 or Any Button(Random) : " host
echo ""
if [[ $host == "1" ]]; then
clear
echo ""
echo ""
echo -e "\e[94;1m╔═════════════════════════════════════════════════╗$NC"
echo -e "\e[1;32m                 INPUT YOUR DOMAIN $NC"
echo -e "\e[94;1m╚═════════════════════════════════════════════════╝ $NC"
echo -e ""
echo -e "\e[91;1m WARNING !! \e[0m"
echo -e "\e[92;1m  # \e[97;1mPastikan Domain anda udah di pointing \e[0m"
echo -e "\e[92;1m  # \e[97;1mPastikan ipvps ter pointing ke domain \e[0m"
echo -e "\e[94;1m═══════════════════════════════════════════════════ $NC"
echo -e "\e[92;1m  # \e[97;1mMake sure your domain is pointed \e[0m"
echo -e "\e[92;1m  # \e[97;1mMake sure ipvps is pointing to the domain \e[0m"
echo -e ""
echo -e "\e[94;1m╚═════════════════════════════════════════════════╝ $NC"
echo ""
echo ""
read -p "   INPUT YOUR DOMAIN :   " host1
echo "IP=" >> /var/lib/kyt/ipvps.conf
echo $host1 > /etc/xray/domain
echo $host1 > /root/domain
echo ""
elif [[ $host == "2" ]]; then
wget ${REPO}Fls/cf.sh && chmod +x cf.sh && ./cf.sh
rm -f /root/cf.sh
clear
else
print_install "Random Subdomain/Domain is Used"
clear
fi
}
clear
#INFO ISP VPS
ISP=$(cat /etc/xray/isp)
CITY=$(cat /etc/xray/city)
IPVPS=$(curl -s ipv4.icanhazip.com)
domain=$(cat /etc/xray/domain)
RAM=$(free -m | awk 'NR==2 {print $2}')
USAGERAM=$(free -m | awk 'NR==2 {print $3}')
MEMOFREE=$(printf '%-1s' "$(free -m | awk 'NR==2{printf "%.2f%%", $3*100/$2 }')")
LOADCPU=$(printf '%-0.00001s' "$(top -bn1 | awk '/Cpu/ { cpu = "" 100 - $8 "%" }; END { print cpu }')")
MODEL=$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')
CORE=$(printf '%-1s' "$(grep -c cpu[0-9] /proc/stat)")
DATEVPS=$(date +'%d/%m/%Y')
TIMEZONE=$(printf '%(%H:%M:%S)T')
SERONLINE=$(uptime -p | cut -d " " -f 2-10000)
clear
restart_system() {
USRSC=$(wget -qO- https://raw.githubusercontent.com/rwrtx/vvipsc/main/izin | grep $ipsaya | awk '{print $2}')
EXPSC=$(wget -qO- https://raw.githubusercontent.com/rwrtx/vvipsc/main/izin | grep $ipsaya | awk '{print $3}')
TIMEZONE=$(printf '%(%H:%M:%S)T')
TEXT="
<code>────────────────────</code>
<b>⚡AUTOSCRIPT PREMIUM⚡</b>
<code>────────────────────</code>
<code>Owner    :</code><code>$username</code>
<code>OS LINUX :</code><code>$MODEL</code>
<code>Domain   :</code><code>$domain</code>
<code>IP VPS   :</code><code>$MYIP</code>
<code>DATE     :</code><code>$DATE</code>
<code>Time     :</code><code>$TIMEZONE</code>
<code>Exp Sc.  :</code><code>$exp</code>
<code>────────────────────</code>
<b> ❖ TomattoVPN  TUNNELING ❖  </b>
<code>────────────────────</code>
<i>Automatic Notifications From Github</i>
"'&reply_markup={"inline_keyboard":[[{"text":"ᴏʀᴅᴇʀ","url":"https://t.me/"}]]}' 
curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
}
clear
function pasang_ssl() {
clear
print_install "Memasang SSL Pada Domain"
rm -rf /etc/xray/xray.key
rm -rf /etc/xray/xray.crt
domain=$(cat /root/domain)
STOPWEBSERVER=$(lsof -i:80 | cut -d' ' -f1 | awk 'NR==2 {print $1}')
rm -rf /root/.acme.sh
mkdir /root/.acme.sh
systemctl stop $STOPWEBSERVER
systemctl stop nginx
curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
chmod +x /root/.acme.sh/acme.sh
/root/.acme.sh/acme.sh --upgrade --auto-upgrade
/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
/root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
chmod 777 /etc/xray/xray.key
print_success "SSL Certificate"
}

function make_folder_xray() {
rm -rf /etc/vmess/.vmess.db
rm -rf /etc/vless/.vless.db
rm -rf /etc/trojan/.trojan.db
rm -rf /etc/shadowsocks/.shadowsocks.db
rm -rf /etc/ssh/.ssh.db
rm -rf /etc/bot/.bot.db
rm -rf /etc/noobz/.noobzvpns.db
mkdir -p /etc/bot
mkdir -p /etc/xray
mkdir -p /etc/vmess
mkdir -p /etc/vless
mkdir -p /etc/trojan
mkdir -p /etc/shadowsocks
mkdir -p /etc/ssh
mkdir -p /usr/bin/xray/
mkdir -p /var/log/xray/
mkdir -p /var/www/html
mkdir -p /etc/kyt/limit/vmess/ip
mkdir -p /etc/kyt/limit/vless/ip
mkdir -p /etc/kyt/limit/trojan/ip
mkdir -p /etc/kyt/limit/ssh/ip
mkdir -p /etc/limit/vmess
mkdir -p /etc/limit/vless
mkdir -p /etc/limit/trojan
mkdir -p /etc/limit/ssh
mkdir -p /etc/noobzvpns
mkdir -p /etc/limit/noobzvpns/ip
mkdir -p /etc/limit/noobzvpns/quota
mkdir -p /etc/limit/noobzvpns
chmod +x /var/log/xray
touch /etc/xray/domain
touch /var/log/xray/access.log
touch /var/log/xray/error.log
touch /etc/vmess/.vmess.db
touch /etc/vless/.vless.db
touch /etc/trojan/.trojan.db
touch /etc/shadowsocks/.shadowsocks.db
touch /etc/ssh/.ssh.db
touch /etc/bot/.bot.db
touch /etc/.noobzvpns.db
echo "& plughin Account" >>/etc/vmess/.vmess.db
echo "& plughin Account" >>/etc/vless/.vless.db
echo "& plughin Account" >>/etc/trojan/.trojan.db
echo "& plughin Account" >>/etc/shadowsocks/.shadowsocks.db
echo "& plughin Account" >>/etc/ssh/.ssh.db
echo "& plughin Account" >>/etc/noobzvpns/.noobzvpns.db
}
function install_xray() {
clear
print_install "Installing Xray Core (Latest Stable)"
domainSock_dir="/run/xray";! [ -d $domainSock_dir ] && mkdir  $domainSock_dir
chown www-data.www-data $domainSock_dir
latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version $latest_version
wget -O /etc/xray/config.json "${REPO}Cfg/config.json" >/dev/null 2>&1
wget -O /etc/files/config.json "${NOOBZJSON}config.json" >/dev/null 2>&1
wget -O /etc/systemd/system/runn.service "${REPO}Fls/runn.service" >/dev/null 2>&1
domain=$(cat /etc/xray/domain)
IPVS=$(cat /etc/xray/ipvps)
print_success "Xray Core Installed (v$latest_version)"
clear
curl -s ipinfo.io/city >>/etc/xray/city
curl -s ipinfo.io/org | cut -d " " -f 2-10 >>/etc/xray/isp
print_install "Memasang Konfigurasi Packet"
wget -O /etc/haproxy/haproxy.cfg "${REPO}Cfg/haproxy.cfg" >/dev/null 2>&1
wget -O /etc/nginx/conf.d/xray.conf "${REPO}Cfg/xray.conf" >/dev/null 2>&1
sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
curl ${REPO}Cfg/nginx.conf > /etc/nginx/nginx.conf
# pastikan hap.pem selalu ada
if [ -f /etc/xray/xray.crt ] && [ -f /etc/xray/xray.key ]; then
  cat /etc/xray/xray.crt /etc/xray/xray.key > /etc/haproxy/hap.pem
  chmod 600 /etc/haproxy/hap.pem
else
  print_error "SSL belum ada saat konfigurasi haproxy"
  exit 1
fi
chmod +x /etc/systemd/system/runn.service
rm -rf /etc/systemd/system/xray.service.d
cat >/etc/systemd/system/xray.service <<EOF
Description=Xray Service
Documentation=https://github.com
After=network.target nss-lookup.target
[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
filesNPROC=10000
filesNOFILE=1000000
[Install]
WantedBy=multi-user.target
EOF
print_success "Konfigurasi Packet"
}
function ssh(){
clear
print_install "Memasang Password SSH"
wget -O /etc/pam.d/common-password "${REPO}Fls/password"
chmod +x /etc/pam.d/common-password
DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration
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
cd
cat > /etc/systemd/system/rc-local.service <<-END
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
cat > /etc/rc.local <<-END
exit 0
END
chmod +x /etc/rc.local
systemctl enable rc-local
systemctl start rc-local.service
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
print_success "Password SSH"
}
function udp_mini(){
clear
print_install "Memasang Service limit Quota"
wget raw.githubusercontent.com/rwrtx/sctomatto/main/Fls/limit.sh && chmod +x limit.sh && ./limit.sh
cd
wget -q -O /usr/bin/limit-ip "${REPO}Fls/limit-ip"
chmod +x /usr/bin/limit-ip
cd /usr/bin
sed -i 's/\r//' limit-ip
cd
clear
cat >/etc/systemd/system/vmip.service << EOF
[Unit]
Description=My
ProjectAfter=network.target
[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/limit-ip vmip
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl restart vmip
systemctl enable vmip
cat >/etc/systemd/system/vlip.service << EOF
[Unit]
Description=My
ProjectAfter=network.target
[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/limit-ip vlip
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl restart vlip
systemctl enable vlip
cat >/etc/systemd/system/trip.service << EOF
[Unit]
Description=My
ProjectAfter=network.target
[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/limit-ip trip
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl restart trip
systemctl enable trip
mkdir -p /usr/local/kyt/
wget -q -O /usr/local/kyt/udp-mini "${REPO}Fls/udp-mini"
chmod +x /usr/local/kyt/udp-mini
wget -q -O /etc/systemd/system/udp-mini-1.service "${REPO}Fls/udp-mini-1.service"
wget -q -O /etc/systemd/system/udp-mini-2.service "${REPO}Fls/udp-mini-2.service"
wget -q -O /etc/systemd/system/udp-mini-3.service "${REPO}Fls/udp-mini-3.service"
systemctl disable udp-mini-1
systemctl stop udp-mini-1
systemctl enable udp-mini-1
systemctl start udp-mini-1
systemctl disable udp-mini-2
systemctl stop udp-mini-2
systemctl enable udp-mini-2
systemctl start udp-mini-2
systemctl disable udp-mini-3
systemctl stop udp-mini-3
systemctl enable udp-mini-3
systemctl start udp-mini-3
print_success "files Quota Service"
}
function ssh_slow(){
clear
print_install "Memasang modul SlowDNS Server"
wget -q -O /tmp/nameserver "${REPO}Fls/nameserver" >/dev/null 2>&1
chmod +x /tmp/nameserver
bash /tmp/nameserver | tee /root/install.log
clear
print_success "SlowDNS"
}
clear
function ins_SSHD(){
clear
print_install "Memasang SSHD"
wget -q -O /etc/ssh/sshd_config "${REPO}Fls/sshd" >/dev/null 2>&1
chmod 700 /etc/ssh/sshd_config
/etc/init.d/ssh restart
systemctl restart ssh
/etc/init.d/ssh status
print_success "SSHD"
}
clear
function ins_dropbear(){
clear
print_install "Menginstall Dropbear"
apt-get install dropbear -y > /dev/null 2>&1
wget -q -O /etc/default/dropbear "${REPO}Cfg/dropbear.conf"
chmod +x /etc/default/dropbear
/etc/init.d/dropbear restart
/etc/init.d/dropbear status
print_success "Dropbear"
}
clear
function ins_vnstat(){
clear
print_install "Menginstall Vnstat"
apt -y install vnstat > /dev/null 2>&1
/etc/init.d/vnstat restart
apt -y install libsqlite3-dev > /dev/null 2>&1
wget https://humdi.net/vnstat/vnstat-2.6.tar.gz
tar zxvf vnstat-2.6.tar.gz
cd vnstat-2.6
./configure --prefix=/usr --sysconfdir=/etc && make && make install
cd
vnstat -u -i $NET
sed -i 's/Interface "'""eth0""'"/Interface "'""$NET""'"/g' /etc/vnstat.conf
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat
/etc/init.d/vnstat restart
/etc/init.d/vnstat status
rm -f /root/vnstat-2.6.tar.gz
rm -rf /root/vnstat-2.6
print_success "Vnstat"
}
function ins_openvpn(){
clear
print_install "Menginstall OpenVPN"
wget ${REPO}Vpn/openvpn &&  chmod +x openvpn && ./openvpn
/etc/init.d/openvpn restart
print_success "OpenVPN"
}
function ins_backup(){
clear
#print_install "Memasang Backup Server"
apt install rclone -y
printf "q\n" | rclone config
wget -O /root/.config/rclone/rclone.conf "${REPO}Cfg/rclone.conf"
cd /bin
git clone https://github.com/arivpnstores/wondershaper.git
cd wondershaper
sudo make install
cd
rm -rf wondershaper
echo > /home/files
apt install msmtp-mta ca-certificates bsd-mailx -y
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
chown -R www-data:www-data /etc/msmtprc
wget -q -O /etc/ipserver "${REPO}Fls/ipserver" && bash /etc/ipserver
#print_success "Backup Server"
}
clear
function ins_swab(){
clear
#print_install "Memasang Swap 2 GB"
gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v"$gotop_latest"_linux_amd64.deb"
curl -sL "$gotop_link" -o /tmp/gotop.deb
dpkg -i /tmp/gotop.deb >/dev/null 2>&1
dd if=/dev/zero of=/swapfile bs=1M count=2048
mkswap /swapfile
chown root:root /swapfile
chmod 0600 /swapfile >/dev/null 2>&1
swapon /swapfile >/dev/null 2>&1
sed -i '$ i\/swapfile      swap swap   defaults    0 0' /etc/fstab
chronyd -q 'server 0.id.pool.ntp.org iburst'
chronyc sourcestats -v
chronyc tracking -v
wget ${REPO}Fls/bbr.sh &&  chmod +x bbr.sh && ./bbr.sh
#print_success "Swap 2 GB"
}
function ins_Fail2ban(){
clear
print_install "Menginstall Fail2ban (VPN Safe)"

# Install Fail2ban
apt install -y fail2ban

# Banner SSH & Dropbear
echo "Banner /etc/banner.txt" >> /etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/banner.txt"@g' /etc/default/dropbear
wget -q -O /etc/banner.txt "${REPO}Bnr/banner.txt"
wget -O /etc/kyt.txt "${REPO}banner/issue.net"
# Konfigurasi Fail2ban (VPN SAFE)
cat >/etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime  = 1800
findtime = 600
maxretry = 5

ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16

backend = systemd
banaction = iptables-multiport

################################
# SSH PROTECTION
################################
[sshd]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s
maxretry = 5
findtime = 600
bantime  = 3600

################################
# SSH DDOS
################################
[sshd-ddos]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s
maxretry = 10
findtime = 120
bantime  = 3600

################################
# NGINX AUTH (AMAN)
################################
[nginx-http-auth]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/error.log
maxretry = 6

################################
# NGINX BOT SEARCH (AMAN)
################################
[nginx-botsearch]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/access.log
maxretry = 10
findtime = 300
bantime  = 1800

################################
# RECIDIVE (IP BANDAL)
################################
[recidive]
enabled  = true
logpath  = /var/log/fail2ban.log
banaction = iptables-allports[name=recidive]
findtime = 86400
maxretry = 5
bantime  = 604800
EOF

# Restart & Enable Fail2ban
systemctl restart fail2ban
systemctl enable fail2ban

print_success "Fail2ban VPN-Safe Installed"
}

function ins_epro(){
clear
print_install "Menginstall ePro WebSocket Proxy"
wget -O /usr/bin/ws "${REPO}Fls/ws" >/dev/null 2>&1
wget -O /usr/bin/tun.conf "${REPO}Cfg/tun.conf" >/dev/null 2>&1
wget -O /etc/systemd/system/ws.service "${REPO}Fls/ws.service" >/dev/null 2>&1
chmod +x /etc/systemd/system/ws.service
chmod +x /usr/bin/ws
chmod 644 /usr/bin/tun.conf
systemctl disable ws
systemctl stop ws
systemctl enable ws
systemctl start ws
systemctl restart ws
wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" >/dev/null 2>&1
wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" >/dev/null 2>&1
wget -O /usr/sbin/ftvpn "${REPO}Fls/ftvpn" >/dev/null 2>&1
chmod +x /usr/sbin/ftvpn
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload
cd
apt autoclean -y >/dev/null 2>&1
apt autoremove -y >/dev/null 2>&1
print_success "ePro WebSocket Proxy"
}
function ins_restart(){
clear
print_install "Restarting  All Packet"
/etc/init.d/nginx restart
/etc/init.d/openvpn restart
/etc/init.d/ssh restart
/etc/init.d/dropbear restart
/etc/init.d/fail2ban restart
/etc/init.d/vnstat restart
/etc/noobzvpns/noobzvpns restart
systemctl restart haproxy
/etc/init.d/cron restart
systemctl daemon-reload
systemctl restart noobzvpns
systemctl start netfilter-persistent
systemctl enable --now nginx
systemctl enable --now xray
systemctl enable --now rc-local
systemctl enable --now dropbear
systemctl enable --now openvpn
systemctl enable --now cron
systemctl enable --now haproxy
systemctl enable --now netfilter-persistent
systemctl enable --now ws
systemctl enable --now fail2ban
systemctl enable --now noobzvpns
systemctl enable --now udp-custom
history -c
echo "unset HISTFILE" >> /etc/profile
cd
rm -f /root/openvpn
rm -f /root/key.pem
rm -f /root/cert.pem
print_success "All Packet"
}
function menu(){
clear
print_install "Memasang Menu Packet"
wget ${REPO}menu/menu.zip
unzip menu.zip
chmod +x menu/*
mv menu/* /usr/local/sbin
rm -rf menu
rm -rf menu.zip
}
function profile(){
clear
cat >/root/.profile <<EOF
if [ "$BASH" ]; then
if [ -f ~/.bashrc ]; then
. ~/.bashrc
fi
fi
mesg n || true
welcome
EOF
cat >/etc/cron.d/log_clear <<-END
		8 0 * * * root /usr/local/bin/log_clear
	END

cat >/usr/local/bin/log_clear <<-END
#!/bin/bash
tanggal=$(date +"%m-%d-%Y")
waktu=$(date +"%T")
echo "Sucsesfully clear & restart On $tanggal Time $waktu." >> /root/log-clear.txt
systemctl restart udp-custom.service
END
	chmod +x /usr/local/bin/log_clear
	
cat >/etc/cron.d/daily_backup <<-END
		0 23 * * * root /usr/local/bin/daily_backup
	END

cat >/usr/local/bin/daily_backup <<-END
#!/bin/bash
tanggal=$(date +"%m-%d-%Y")
waktu=$(date +"%T")
echo "Sucsesfully Backup On $tanggal Time $waktu." >> /root/log-backup.txt
/usr/local/sbin/backup -r now
END
	chmod +x /usr/local/bin/daily_backup

cat >/etc/cron.d/xp_sc <<-END
		5 2 * * * root /usr/local/bin/xp_sc
	END

cat >/usr/local/bin/xp_sc <<-END
#!/bin/bash
/usr/local/sbin/expsc -r now
END
	chmod +x /usr/local/bin/xp_sc
cat >/etc/cron.d/xp_all <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
2 0 * * * root /usr/local/sbin/xp
END
cat >/etc/cron.d/logclean <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/10 * * * * root /usr/local/sbin/clearlog
END
chmod 644 /root/.profile
cat >/etc/cron.d/daily_reboot <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 5 * * * root /sbin/reboot
END
echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >>/etc/cron.d/log.xray
service cron restart
cat >/home/daily_reboot <<-END
5
END
cat >/etc/systemd/system/rc-local.service <<EOF
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
cat >/etc/rc.local <<EOF
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent
exit 0
EOF
chmod +x /etc/rc.local
AUTOREB=$(cat /home/daily_reboot)
SETT=11
if [ $AUTOREB -gt $SETT ]; then
TIME_DATE="PM"
else
TIME_DATE="AM"
fi
print_success "Menu Packet"
}
function enable_services(){
  clear
  print_install "Enable Service"

  systemctl daemon-reload
  systemctl start netfilter-persistent
  systemctl enable --now rc-local cron netfilter-persistent

  if nginx -t; then
    systemctl restart nginx
  else
    print_error "Config nginx invalid"
    exit 1
  fi

  systemctl restart xray

  if haproxy -c -f /etc/haproxy/haproxy.cfg; then
    systemctl restart haproxy
  else
    print_error "Config haproxy invalid"
    exit 1
  fi

  systemctl restart noobzvpns

  print_success "Enable Service"
}

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
history -c
rm -rf /root/menu
rm -rf /root/*.zip
rm -rf /root/*.sh
rm -rf /root/LICENSE
rm -rf /root/README.md
rm -rf /root/noobzvpns.zip
secs_to_human "$(($(date +%s) - ${start}))"
sudo hostnamectl set-hostname $username
clear
echo -e ""
echo -e ""
echo -e "\e[94;1m╔═════════════════════════════════════════════════╗\e[0m"
echo -e "\e[96;1m          ----[ TomattoVPN TUNNELING ]----                 \e[0m"
echo -e "\e[94;1m╚═════════════════════════════════════════════════╝\e[0m"
echo -e "\e[94;1m╔═════════════════════════════════════════════════╗\e[0m"
echo -e "\e[92;1m            ----[ INSTALL SUCCES ]----                   \e[0m"
echo -e "\e[94;1m╚═════════════════════════════════════════════════╝\e[0m"
echo -e "\e[94;1m╔═════════════════════════════════════════════════╗\e[0m"
echo -e "\e[92;1m               ----[ INFO PORT ]----                      \e[0m"
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
