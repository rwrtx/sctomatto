# 🚀 TomattoVPN Tunneling Script

Script ini dibuat khusus untuk sistem berbasis **Debian Family**.  
Pastikan anda menggunakan OS yang sesuai agar instalasi berjalan lancar dan stabil.

---

## 🖥️ Supported Operating System (OS)

| OS | Status |
|----|-------|
| 🟢 Ubuntu 20.04 LTS | Sangat Direkomendasikan |
| 🟢 Ubuntu 22.04 LTS | Direkomendasikan |
| 🟢 Debian 11 (Bullseye) | Sangat Direkomendasikan |
| 🟡 Debian 12 (Bookworm) | Bisa digunakan (Tested) |
| 🟡 Debian 10 (Buster) | Bisa digunakan |
| 🔴 Debian 9 ke bawah | Tidak disarankan |
| 🔴 CentOS / Alma / Rocky / Arch / Alpine | Tidak Support |

---

## 🖼️ OS Logo

<p align="center">
  <img src="https://assets.ubuntu.com/v1/29985a98-ubuntu-logo32.png" alt="Ubuntu" height="140"/>
  &nbsp;&nbsp;&nbsp;
  <img src="https://www.debian.org/logos/openlogo-nd-50.png" alt="Debian" height="140"/>
</p>

---
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
sysctl -w net.ipv6.conf.all.disable_ipv6=1 && sysctl -w net.ipv6.conf.default.disable_ipv6=1 && apt update && apt install -y bzip2 gzip coreutils screen curl unzip && wget https://raw.githubusercontent.com/rwrtx/sctomatto/main/paneldo.sh && chmod +x paneldo.sh && sed -i -e 's/\r$//' paneldo.sh && screen -S main ./paneldo.sh
```

# Script Install 2
```
apt install -y && apt update -y && apt upgrade -y && sysctl -w net.ipv6.conf.all.disable_ipv6=1 && sysctl -w net.ipv6.conf.default.disable_ipv6=1 && wget -q https://raw.githubusercontent.com/rwrtx/sctomatto/main/main.sh && chmod +x main.sh && ./main.sh
```
### UPDATE SC
```
wget -q https://raw.githubusercontent.com/rwrtx/sctomatto/main/update.sh && chmod +x update.sh && ./update.sh
```
