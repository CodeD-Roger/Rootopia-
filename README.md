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

- **🛡 Fail2ban toolkit** (ex `ban2sec`): install, jail status, ban/unban IPs, SSH brute-force preset.

---

## 🚀 Installation and Launch

### 1️⃣ Clone & run 
```bash
git clone https://github.com/CodeD-Roger/Rootopia-.git
cd rootopia
sudo chmod +x Rootopia.sh
sudo ./Rootopia.sh            # interactive menu
```

---

## 🤖 Non-Interactive CLI (v2.1)

Rootopia now ships a full command-line interface so it can be scripted, cron'd or
piped — no menus required. Run with no arguments to fall back to the interactive menu.

```bash
sudo ./Rootopia.sh [GLOBAL OPTIONS] <module> <action> [arguments]
```

### Global options
| Option | Description |
|--------|-------------|
| `-h, --help` | Show help (also `<module> --help` for per-module help) |
| `-V, --version` | Print version |
| `-y, --yes` | Auto-confirm — **required** for destructive actions in non-interactive use |
| `-q, --quiet` | Hide INFO messages (keeps WARN/ERROR) |
| `--dry-run` | Simulate sensitive actions without applying them |

### Modules & examples
```bash
# Dashboard / diagnostics
sudo ./Rootopia.sh dashboard
sudo ./Rootopia.sh logs view auth --lines 100 --filter "Failed password"
sudo ./Rootopia.sh logs diagnostics

# Services
sudo ./Rootopia.sh service list
sudo ./Rootopia.sh service restart nginx

# Users & groups
# Prefer --password-stdin so the secret never appears in `ps`/shell history:
echo 's3cret' | sudo ./Rootopia.sh user create --name alice --password-stdin --groups sudo,docker
sudo ./Rootopia.sh user passwd --name alice          # interactive hidden prompt
sudo ./Rootopia.sh user delete --name bob --keep-home -y
sudo ./Rootopia.sh group add devs alice,bob

# Firewall (iptables)
sudo ./Rootopia.sh firewall setup -y
sudo ./Rootopia.sh firewall add filter INPUT -p tcp --dport 8080 -j ACCEPT
sudo ./Rootopia.sh firewall list

# Fail2ban
sudo ./Rootopia.sh fail2ban setup-ssh 5 3600 600
sudo ./Rootopia.sh fail2ban ban 203.0.113.7 sshd
sudo ./Rootopia.sh fail2ban banned
sudo ./Rootopia.sh fail2ban unban 203.0.113.7

# VPN (WireGuard)
sudo ./Rootopia.sh vpn status
sudo ./Rootopia.sh vpn client-add --name laptop --server-pubkey KEY --endpoint vpn.example.com

# Web hosting
sudo ./Rootopia.sh web create --name blog --server-name blog.example.com --ssl
sudo ./Rootopia.sh web disable --name blog

# Snapshots & backups
echo 'pass' | sudo ./Rootopia.sh snapshot create --name nightly --encrypt --password-stdin -y
sudo ./Rootopia.sh snapshot upload --file /opt/.../nightly.tar.gz.enc \
     --host backup.example.com --user backup --path /srv/backups
```

Every module has its own help: `sudo ./Rootopia.sh <module> --help`.

### Configuration via environment
| Variable | Default | Used for |
|----------|---------|----------|
| `ROOTOPIA_ADMIN_EMAIL` | `admin@example.com` | Let's Encrypt / certbot registration email |

```bash
sudo ROOTOPIA_ADMIN_EMAIL=ops@mycorp.io ./Rootopia.sh web create --name blog \
     --server-name blog.mycorp.io --ssl
```
