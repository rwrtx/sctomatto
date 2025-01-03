#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# System Request : Debian 9+/Ubuntu 18.04+/20+
# Developer      : R32WRT_STORE
# Telegram       : https://t.me/R32WRT_STORE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# R32WRTx TUNNELING (BOT 2 INSTALL)

NS=$(cat /etc/xray/dns)
PUB=$(cat /etc/slowdns/server.pub)
domain=$(cat /etc/xray/domain)

# Color
grenbo="\e[92;1m"
NC='\e[0m'

# Install dependencies
apt update && apt upgrade -y
apt install python3 python3-pip git wget unzip -y

# Create directory for Bot 2
BOT_DIR="/usr/bin/bot2"
KY_DIR="/usr/bin/kyt2"
mkdir -p "$BOT_DIR"
mkdir -p "$KY_DIR"

# Download and extract bot2.zip
wget -O bot2.zip "https://raw.githubusercontent.com/rwrtx/sctomatto/main/bot/bot2.zip"
unzip -o bot2.zip -d "$BOT_DIR"
chmod +x "$BOT_DIR"/*
rm -f bot2.zip

# Download and extract kyt2.zip
wget -O kyt2.zip "https://raw.githubusercontent.com/rwrtx/sctomatto/main/bot/kyt2.zip"
unzip -o kyt2.zip -d "$KY_DIR"
pip3 install -r "$KY_DIR/requirements.txt"
rm -f kyt2.zip

# Prompt user for input
clear
echo ""
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\e[1;97;101m           » TAMBAH BOT PANEL «           \e[0m"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "${grenbo}Tutorial Create Bot and ID Telegram${NC}"
echo -e "${grenbo}[»] Create Bot and Token Bot : @BotFather${NC}"
echo -e "${grenbo}[»] Info Id Telegram : @MissRose_bot${NC}"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e ""
read -e -p "[»] Input your Bot Token   : " bottoken
read -e -p "[»] Input Your Id Telegram : " admin
echo -e BOT_TOKEN='"'$bottoken'"' >> "$KY_DIR/var.txt"
echo -e ADMIN='"'$admin'"' >> "$KY_DIR/var.txt"
echo -e DOMAIN='"'$domain'"' >> "$KY_DIR/var.txt"
echo -e PUB='"'$PUB'"' >> "$KY_DIR/var.txt"
echo -e HOST='"'$NS'"' >> "$KY_DIR/var.txt"

# Configure Bot 2 as a systemd service
cat > /etc/systemd/system/kyt2.service << END
[Unit]
Description=Simple kyt2 - @kyt
After=network.target

[Service]
WorkingDirectory=$KY_DIR
ExecStart=/usr/bin/python3 -m kyt2
Restart=always

[Install]
WantedBy=multi-user.target
END

systemctl start kyt2
systemctl enable kyt2
systemctl restart kyt2

# Output confirmation
clear
echo "Input Data Berhasil Diproses!"
echo "Your Data Bot Telegram"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Token Bot      : $bottoken"
echo "Admin          : $admin"
echo "Domain         : $domain"
echo "Pub            : $PUB"
echo "Host           : $NS"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Setting Bot Success!"
sleep 2
clear

echo "Installation complete, type /menu on your bot"
read -p "Press Enter to exit"
m-bot
