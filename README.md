<p align="center">
<img src="https://readme-typing-svg.demolab.com?font=Capriola&size=40&duration=5500&pause=450&color=F70069&background=FFFFAA00&center=true&random=false&width=600&height=100&lines=TomattoVPN TUNNELING 🧿" />
</p>

### UPDATE UNTUK DEBIAN
Masukkan perintah dibawah jika anda menggunakan OS Debian Version 9 atau 10
```
apt update -y && apt upgrade -y && apt dist-upgrade -y && reboot
```
### UPDATE UNTUK UBUNTU
Masukkan perintah dibawah jika anda menggunakan OS Ubuntu Version 18 atau 20
```
apt update && apt upgrade -y && update-grub && sleep 2 && reboot
```

### INSTALISASI
# Script Install 1
```
sysctl -w net.ipv6.conf.all.disable_ipv6=1 && sysctl -w net.ipv6.conf.default.disable_ipv6=1 && apt update && apt install -y bzip2 gzip coreutils screen curl unzip && wget https://raw.githubusercontent.com/rwrtx/sctomatto/main/main.sh && chmod +x main.sh && sed -i -e 's/\r$//' main.sh && screen -S main ./main.sh
```

# Script Install 2
```
apt install -y && apt update -y && apt upgrade -y && sysctl -w net.ipv6.conf.all.disable_ipv6=1 && sysctl -w net.ipv6.conf.default.disable_ipv6=1 && wget -q https://raw.githubusercontent.com/rwrtx/sctomatto/main/main.sh && chmod +x main.sh && ./main.sh
```
### UPDATE SC
```
wget -q https://raw.githubusercontent.com/rwrtx/sctomatto/main/update.sh && chmod +x update.sh && ./update.sh
```
