#!/bin/bash
clear
red() { echo -e "\\033[32;1m${*}\\033[0m"; }

# Izin Script
MYIP=$(curl -sS ipv4.icanhazip.com)
echo -e "\e[32mLoading...\e[0m"
clear

# Get Bot
CHATID=$(grep -E "^#bot# " "/etc/bot/.bot.db" | cut -d ' ' -f 3)
KEY=$(grep -E "^#bot# " "/etc/bot/.bot.db" | cut -d ' ' -f 2)
export TIME="10"
export URL="https://api.telegram.org/bot$KEY/sendMessage"
clear

# Valid Script
ipsaya=$(curl -sS ipv4.icanhazip.com)
data_server=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
date_list=$(date +"%Y-%m-%d" -d "$data_server")
data_ip="https://raw.githubusercontent.com/rwrtx/vvipsc/main/ip"
checking_sc() {
  useexp=$(wget -qO- $data_ip | grep $ipsaya | awk '{print $3}')
  if [[ $date_list < $useexp ]]; then
    echo -ne
  else
    echo -e "\033[1;93m────────────────────────────────────────────\033[0m"
    echo -e "\033[42m          404 NOT FOUND AUTOSCRIPT          \033[0m"
    echo -e "\033[1;93m────────────────────────────────────────────\033[0m"
    echo -e "\n            \033[91;1mPERMISSION DENIED!\033[0m"
    echo -e "Your VPS $ipsaya has been banned."
    echo -e "Contact Admin: t.me/TomattoVPN"
    echo -e "\033[1;93m────────────────────────────────────────────\033[0m"
    sleep 10
    reboot
  fi
}
checking_sc
clear

# Getting Info
IP=$(curl -sS ipv4.icanhazip.com)
ISP=$(cat /etc/xray/isp)
CITY=$(cat /etc/xray/city)
domain=$(cat /etc/xray/domain)
nama=$(cat /etc/xray/username)
clear

# Banner Functions
function baris_panjang() {
  echo -e "\033[5;36m ◇━━━━━━━━━━━━━━━━━◇ \033[0m"
}

function xdxl_Banner() {
  clear
  baris_panjang
  echo -e "\033[95;1m     $nama       \033[0m"
  baris_panjang
}

# Sc_Credit Function
function Sc_Credit() {
  sleep 1
  baris_panjang
  echo -e "\033[2;35m      Terimakasih Telah Menggunakan \033[0m"
  echo -e "\033[2;35m             Script Credit \033[0m"
  echo -e "\033[2;35m          $nama  \033[0m"
  baris_panjang
  systemctl restart xray > /dev/null 2>&1
  service cron restart > /dev/null 2>&1
  exit 1
}

# Loading Function
function loading() {
  local pid=$1
  local delay=0.1
  local spin='-\|/'

  while ps -p $pid > /dev/null; do
    local temp=${spin#?}
    printf "[%c] " "$spin"
    local spin=$temp${spin%"$temp"}
    sleep $delay
    printf "\b\b\b\b\b\b"
  done

  printf "    \b\b\b\b"
}

# Main Recovery Function
function recovery_akun() {
  # Get username to recover
  xdxl_Banner
  baris_panjang
  echo -e "\033[37mPlease enter the username for recovery:\033[0m"
  read -p "Username: " user
  if [[ -z "$user" ]]; then
    echo -e "\033[91mInvalid username, exiting...\033[0m"
    exit 1
  fi

  # Check if user exists
  CLIENT_EXISTS=$(grep -w "$user" /etc/xray/config.json | wc -l)
  if [[ $CLIENT_EXISTS != "1" ]]; then
    echo -e "\033[91mUsername not found, please check again.\033[0m"
    exit 1
  fi

  # Get the user UUID and expiration date
  uuid=$(grep -w "$user" /etc/xray/config.json | cut -d " " -f 3)
  exp_date=$(grep -w "$user" /etc/xray/config.json | cut -d " " -f 5)

  # Show current details for recovery
  echo -e "User: $user"
  echo -e "UUID: $uuid"
  echo -e "Expiration Date: $exp_date"
  echo -e "\nDo you want to proceed with recovery? (y/n)"
  read -p "Choice: " choice
  if [[ "$choice" != "y" ]]; then
    echo -e "\033[91mAborted.\033[0m"
    exit 1
  fi

  # Recovery procedure
  echo -e "Enter new expiration days for the account (e.g., 30 days):"
  read -p "New Expiration Days: " new_exp_days
  if [[ -z "$new_exp_days" ]]; then
    echo -e "\033[91mInvalid input.\033[0m"
    exit 1
  fi

  # Update expiration date and config
  new_exp=$(date -d "$new_exp_days days" +"%Y-%m-%d")
  sed -i "/$user/ s/$exp_date/$new_exp/" /etc/xray/config.json

  # Generate a new link
  vmess_json="{
    \"v\": \"2\",
    \"ps\": \"$user\",
    \"add\": \"$domain\",
    \"port\": \"443\",
    \"id\": \"$uuid\",
    \"aid\": \"0\",
    \"net\": \"ws\",
    \"path\": \"/vmess\",
    \"type\": \"none\",
    \"host\": \"$domain\",
    \"tls\": \"tls\"
  }"
  vmesslink="vmess://$(echo "$vmess_json" | base64 -w 0)"

  # Save new link to file
  echo "$vmesslink" > "/var/www/html/vmess-$user-recovered.txt"

  # Notify via Telegram
  TEXT="<code>Recovery for VMESS account</code>\nLink: $vmesslink\nNew Expiry: $new_exp_days days"
  curl -s --max-time $TIME -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null

  echo -e "\033[92mAccount recovery successful!\033[0m"
}

# Run the recovery
recovery_akun
