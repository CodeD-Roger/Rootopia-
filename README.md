# 🧙 Rootopia - The Magical Linux Management Script
---

`rootopia.sh` is a **comprehensive and interactive Bash script** designed to be your all-in-one control panel for managing users, services, firewalls, backups, VPNs, and websites—right from your terminal.

Think of it as your own little sysadmin utopia… but with more power and fewer headaches. 🧠⚡

---

## 🌟 What It Does

- **🛠 Manage users and groups** like a wizard (create, delete, password reset, group juggling).
- **📡 Control services** (start, stop, enable, view logs, edit config).
- **🧱 Configure iptables firewall** with secure defaults and custom rules.
- **🔐 WireGuard VPN support**, including client generation and management.
- **🌐 Host and manage websites** via Nginx, with auto SSL (via certbot or self-signed).
- **🕵️ System diagnostics** with live summaries, resource usage, and health checks.
- **🧞 Snapshots and backups**, including Docker volumes and databases, with optional encryption.
- **☁️ Push snapshots to remote servers** via SCP for peace of mind.

---

## 🧭 Menu Highlights

- **📊 Live system dashboard**: hostname, IPs, uptime, active users, VPN status, services.
- **👥 User and group wizardry**: list, create, delete, update, group magic.
- **📋 Service control**: Nginx, Docker, MariaDB, SSH, VPN, etc.
- **🧰 Iptables Firewall Toolkit**: list/add/delete rules, save/restore, basic secure preset.
- **🔌 VPN center**: toggle, check status, create/revoke clients.
- **🪄 Web hosting manager**: create/destroy websites, enable SSL, toggle virtual hosts.
- **💾 Snapshot & Backup Suite**: databases, configs, volumes, with encryption support.
- **⏰ Auto-backup scheduler**: via crontab, set daily/weekly/monthly plans.

---

## 🚀 Installation and Launch

### 1️⃣ Clone & run 
```bash
git clone https://github.com/CodeD-Roger/Rootopia-.git
cd rootopia
sudo chmod +x rootopia.sh
sudo ./rootopia.sh
```
