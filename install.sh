#!/bin/bash
MYIP=$(curl -sS ipv4.icanhazip.com)
cp /media/cybervpn/var.txt /tmp
cp /root/cybervpn/var.txt /tmp
rm -rf cybervpn
apt update && apt upgrade -y
apt install python3 python3-pip -y
apt install sqlite3 -y
cd /media/
rm -rf cybervpn
wget https://raw.githubusercontent.com/rwrtx/sctomatto/main/ping/cybervpn.zip
unzip cybervpn.zip
cd cybervpn
rm var.txt
rm database.db
pip3 install -r requirements.txt
pip install pillow
pip install speedtest-cli
pip3 install aiohttp
pip3 install paramiko
clear
rm -rf bot
rm bot.*
cd /usr/bin
wget https://raw.githubusercontent.com/rwrtx/sctomatto/main/ping/bot.zip
unzip bot.zip
mv bot/* /usr/bin
chmod +x /usr/bin/*
rm -rf bot.zip
#isi data
nsdom=$(cat /root/nsdomain)
domain=$(cat /etc/xray/domain)
clear
clear
echo
echo -e "\033[97m◇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━◇\033[0m"
echo -e " \033[1;97;41m          ADD BOT CYBERVPN         \033[0m"
echo -e "\033[97m◇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━◇\033[0m"
read -e -p "Masukkan Bot Token: " token
read -e -p "Masukkan ID Telegram :" admin

echo "$token" > /root/.notifbot
echo "$admin" >> /root/.notifbot

cat > /media/cybervpn/var.txt << END
ADMIN="$admin"
BOT_TOKEN="$token"
DOMAIN="$domain"
DNS="$nsdom"
PUB="7fbd1f8aa0abfe15a7903e837f78aba39cf61d36f183bd604daa2fe4ef3b7b59"
OWN="$user"
SALDO="100000"
END


clear
echo "Done"
echo "Your Data Bot"
echo -e "==============================="
echo "Api Token     : $token"
echo "ID            : $admin"
echo "DOMAIN        : $domain"
echo -e "==============================="
echo "Setting done"


rm -f /usr/bin/nenen

echo -e '#!/bin/bash\ncd /media/\npython3 -m cybervpn' > /usr/bin/nenen


chmod 777 /usr/bin/nenen

cat > /etc/systemd/system/cybervpn.service << END
[Unit]
Description=Simple CyberVPN - @CyberVPN
After=network.target

[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/nenen
Restart=always

[Install]
WantedBy=multi-user.target

END
systemctl daemon-reload
systemctl start cybervpn
systemctl enable cybervpn
clear
loading() {
  local pid=$1
  local delay=0.1
  local spin='-\|/'

  while ps -p "$pid" > /dev/null; do
    printf "[%c] " "$spin"
    spin=${spin#?}${spin%"${spin#?}"}
    sleep $delay
    printf "\b\b\b\b\b\b"
  done

  printf "    \b\b\b\b"
}

echo -e " \033[1;97;41m     MENDOWNLOAD ASSET TAMBAHAN......    \033[0m"

sleep 2 & loading $! & wget -q -O /media/log-install.txt "https://raw.githubusercontent.com/rwrtx/sctomatto/main/ping/log-install.txt"

sleep 2 & loading $! & wget -q -O /usr/bin/addnoobz "https://raw.githubusercontent.com/rwrtx/sctomatto/main/ping/addnoobz.sh" && chmod +x /usr/bin/addnoobz

sleep 2 & loading $! & wget -q -O /usr/bin/cek-ssh "https://raw.githubusercontent.com/rwrtx/sctomatto/main/ping/cek-ssh.sh" && chmod +x /usr/bin/cek-ssh

sleep 2 & loading $! & wget -q -O /usr/bin/cek-ss "https://raw.githubusercontent.com/rwrtx/sctomatto/main/ping/cek-ss.sh" && chmod +x /usr/bin/cek-ss

sleep 2 & loading $! & wget -q -O /usr/bin/cek-tr "https://raw.githubusercontent.com/rwrtx/sctomatto/main/ping/cek-tr.sh" && chmod +x /usr/bin/cek-tr

sleep 2 & loading $! & wget -q -O /usr/bin/cek-vless "https://raw.githubusercontent.com/rwrtx/sctomatto/main/ping/cek-vless.sh" && chmod +x /usr/bin/cek-vless

sleep 2 & loading $! & wget -q -O /usr/bin/cek-ws "https://raw.githubusercontent.com/rwrtx/sctomatto/main/ping/cek-ws.sh" && chmod +x /usr/bin/cek-ws

sleep 2 & loading $! & wget -q -O /usr/bin/del-vless "https://raw.githubusercontent.com/rwrtx/sctomatto/main/ping/del-vless.sh" && chmod +x /usr/bin/del-vless

sleep 2 & loading $! & wget -q -O /usr/bin/cek-noobz "https://raw.githubusercontent.com/rwrtx/sctomatto/main/ping/cek-noobz.sh" && chmod +x /usr/bin/cek-noobz

sleep 2 & loading $! & wget -q -O /usr/bin/cek-mws "https://raw.githubusercontent.com/rwrtx/sctomatto/main/ping/cek-mws.sh" && chmod +x /usr/bin/cek-mws

sleep 2 & loading $! & wget -q -O /usr/bin/cek-mvs "https://raw.githubusercontent.com/rwrtx/sctomatto/main/ping/cek-mvs.sh" && chmod +x /usr/bin/cek-mvs

sleep 2 & loading $! & wget -q -O /usr/bin/cek-mss "https://raw.githubusercontent.com/rwrtx/sctomatto/main/ping/cek-mss.sh" && chmod +x /usr/bin/cek-mss

sleep 2 & loading $! & wget -q -O /usr/bin/cek-mts "https://raw.githubusercontent.com/rwrtx/sctomatto/main/ping/cek-mts.sh" && chmod +x /usr/bin/cek-mts
clear
cp /tmp/var.txt /media/cybervpn
rm -rf bot.sh
rm -rf bot.sh.1
clear
rm /media/cybervpn.zip
echo " Installations complete, type /menu on your bot"
read -n 1 -s -r -p "Press [ Enter ] to back on menu"
menu

