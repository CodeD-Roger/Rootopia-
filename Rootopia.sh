#!/bin/bash
export PATH=$PATH:/usr/sbin:/sbin
# EcoManage - Système de Gestion Linux Centralisé
# Script principal pour la gestion des services, utilisateurs, sécurité et sauvegardes

# Variables globales
LOG_FILE="/var/log/ecomanage.log"
SNAPSHOT_DIR="/opt/ecomanage/snapshots"
CONFIG_DIR="/opt/ecomanage/config"
WEB_ROOT="/var/www"
IPTABLES_RULES="/etc/iptables/rules.v4"

# Fonction pour journaliser les actions
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    # Afficher également dans la console si ce n'est pas silencieux
    if [ "$3" != "silent" ]; then
        echo "[$level] $message"
    fi
}

# Vérification des privilèges root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log "ERROR" "Ce script doit être exécuté en tant que root"
        exit 1
    fi
}

# Création des répertoires nécessaires
setup_directories() {
    mkdir -p "$SNAPSHOT_DIR" "$CONFIG_DIR"
    chmod 700 "$SNAPSHOT_DIR" "$CONFIG_DIR"
    log "INFO" "Répertoires de configuration créés" "silent"
}

# Vérification et installation des dépendances
check_dependencies() {
  log "INFO" "Vérification des dépendances..."
  
  # Liste des commandes requises
  required_commands=("useradd" "userdel" "usermod" "groupadd" "groupdel" "chpasswd" "iptables")
  missing_commands=()
  
  for cmd in "${required_commands[@]}"; do
    if ! command -v "$cmd" &>/dev/null; then
      missing_commands+=("$cmd")
    fi
  done
  
  if [ ${#missing_commands[@]} -ne 0 ]; then
    log "WARN" "Commandes manquantes: ${missing_commands[*]}"
    
    # Détection de la distribution
    if [ -f /etc/debian_version ]; then
      log "INFO" "Distribution Debian/Ubuntu détectée"
      log "INFO" "Installation des paquets nécessaires..."
      apt-get update
      apt-get install -y passwd login adduser iptables
    elif [ -f /etc/redhat-release ]; then
      log "INFO" "Distribution RedHat/CentOS/Fedora détectée"
      log "INFO" "Installation des paquets nécessaires..."
      yum install -y passwd shadow-utils iptables
    elif [ -f /etc/alpine-release ]; then
      log "INFO" "Distribution Alpine détectée"
      log "INFO" "Installation des paquets nécessaires..."
      apk add --no-cache shadow iptables
    else
      log "ERROR" "Distribution non reconnue. Veuillez installer manuellement les paquets nécessaires."
      return 1
    fi
    
    # Vérifier à nouveau après installation
    for cmd in "${missing_commands[@]}"; do
      if ! command -v "$cmd" &>/dev/null; then
        log "ERROR" "Impossible d'installer la commande $cmd"
        return 1
      fi
    done
    
    log "INFO" "Toutes les dépendances sont maintenant installées"
  else
    log "INFO" "Toutes les dépendances sont déjà installées" "silent"
  fi
  
  return 0
}

# ===== MODULE: TABLEAU DE BORD =====

# Obtenir un résumé du système
get_system_summary() {
    log "INFO" "Génération du résumé système..."
    
    # Informations système
    hostname=$(hostname)
    os_info=$(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)
    kernel=$(uname -r)
    uptime=$(uptime -p)
    
    # Informations réseau
    local_ip=$(hostname -I | awk '{print $1}')
    public_ip=$(curl -s https://api.ipify.org)
    
    # Vérifier si VPN est actif
    vpn_active="Non"
    if systemctl is-active --quiet wg-quick@wg0; then
        vpn_active="Oui"
    fi
    
    # Utilisateurs connectés
    logged_users=$(who | wc -l)
    
    # Services critiques
    services=("docker" "nginx" "ssh" "mariadb" "wg-quick@wg0" "vsftpd")
    services_status=""
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            services_status="$services_status\n$service: Actif"
        else
            services_status="$services_status\n$service: Inactif"
        fi
    done
    
    # Dernières erreurs de log
    recent_errors=$(grep -i error /var/log/syslog | tail -10)
    
    # Affichage du résumé
    echo -e "\n===== RÉSUMÉ DU SYSTÈME ====="
    echo -e "Hostname: $hostname"
    echo -e "OS: $os_info"
    echo -e "Kernel: $kernel"
    echo -e "Uptime: $uptime"
    echo -e "\n===== RÉSEAU ====="
    echo -e "IP Locale: $local_ip"
    echo -e "IP Publique: $public_ip"
    echo -e "VPN Actif: $vpn_active"
    echo -e "\n===== UTILISATEURS ====="
    echo -e "Utilisateurs connectés: $logged_users"
    echo -e "\n===== SERVICES ====="
    echo -e "$services_status"
    echo -e "\n===== DERNIÈRES ERREURS ====="
    echo -e "$recent_errors"
}

# ===== MODULE: GESTION DES SERVICES =====

# Lister tous les services
list_services() {
    log "INFO" "Listage des services..."
    
    # Services prédéfinis à surveiller
    services=("docker" "nginx" "ssh" "mariadb" "wg-quick@wg0" "vsftpd")
    
    echo -e "\n===== STATUT DES SERVICES ====="
    printf "%-20s %-15s %-15s %-15s\n" "SERVICE" "STATUT" "DÉMARRAGE AUTO" "PORTS"
    
    for service in "${services[@]}"; do
        # Vérifier le statut
        if systemctl is-active --quiet "$service"; then
            status="Actif"
        else
            status="Inactif"
        fi
        
        # Vérifier si activé au démarrage
        if systemctl is-enabled --quiet "$service" 2>/dev/null; then
            autostart="Activé"
        else
            autostart="Désactivé"
        fi
        
        # Obtenir les ports (si disponible)
        ports=$(ss -tulpn | grep "$service" | awk '{print $5}' | cut -d':' -f2 | sort -u | tr '\n' ',' | sed 's/,$//')
        if [ -z "$ports" ]; then
            ports="-"
        fi
        
        printf "%-20s %-15s %-15s %-15s\n" "$service" "$status" "$autostart" "$ports"
    done
}

# Gérer un service (start/stop/restart/status/enable/disable)
manage_service() {
    local service="$1"
    local action="$2"
    
    log "INFO" "Gestion du service $service: $action"
    
    case "$action" in
        start)
            systemctl start "$service"
            ;;
        stop)
            systemctl stop "$service"
            ;;
        restart)
            systemctl restart "$service"
            ;;
        status)
            systemctl status "$service"
            ;;
        enable)
            systemctl enable "$service"
            ;;
        disable)
            systemctl disable "$service"
            ;;
        logs)
            journalctl -u "$service" --no-pager | tail -n 50
            ;;
        *)
            log "ERROR" "Action non reconnue: $action"
            return 1
            ;;
    esac
    
    if [ $? -eq 0 ]; then
        log "INFO" "Action $action réussie pour $service"
        return 0
    else
        log "ERROR" "Action $action échouée pour $service"
        return 1
    fi
}

# Afficher/Éditer la configuration d'un service
edit_service_config() {
    local service="$1"
    
    log "INFO" "Édition de la configuration pour $service"
    
    # Déterminer le fichier de configuration en fonction du service
    case "$service" in
        nginx)
            config_file="/etc/nginx/nginx.conf"
            ;;
        vsftpd)
            config_file="/etc/vsftpd.conf"
            ;;
        ssh)
            config_file="/etc/ssh/sshd_config"
            ;;
        docker)
            config_file="/etc/docker/daemon.json"
            ;;
        "wg-quick@wg0")
            config_file="/etc/wireguard/wg0.conf"
            ;;
        mariadb)
            config_file="/etc/mysql/mariadb.conf.d/50-server.cnf"
            ;;
        *)
            log "ERROR" "Service non reconnu ou fichier de configuration non défini"
            return 1
            ;;
    esac
    
    # Vérifier si le fichier existe
    if [ ! -f "$config_file" ]; then
        log "ERROR" "Fichier de configuration non trouvé: $config_file"
        return 1
    fi
    
    # Ouvrir avec l'éditeur par défaut
    ${EDITOR:-nano} "$config_file"
    
    # Vérifier la configuration si possible
    case "$service" in
        nginx)
            nginx -t
            if [ $? -eq 0 ]; then
                log "INFO" "Configuration nginx valide"
            else
                log "ERROR" "Configuration nginx invalide"
                return 1
            fi
            ;;
        ssh)
            sshd -t
            if [ $? -eq 0 ]; then
                log "INFO" "Configuration SSH valide"
            else
                log "ERROR" "Configuration SSH invalide"
                return 1
            fi
            ;;
    esac
    
    log "INFO" "Configuration éditée pour $service"
    return 0
}

# ===== MODULE: GESTION DES UTILISATEURS ET GROUPES =====

# Lister tous les utilisateurs
list_users() {
    log "INFO" "Listage des utilisateurs..."
    
    echo -e "\n===== UTILISATEURS SYSTÈME ====="
    printf "%-20s %-15s %-30s %-20s\n" "NOM" "UID" "RÉPERTOIRE" "SHELL"
    
    # Filtrer pour n'afficher que les utilisateurs réels (UID >= 1000 ou utilisateurs spécifiques)
    awk -F: '$3 >= 1000 || $1 == "ftp" || $1 == "www-data" {print $1, $3, $6, $7}' /etc/passwd | \
    while read -r username uid homedir shell; do
        printf "%-20s %-15s %-30s %-20s\n" "$username" "$uid" "$homedir" "$shell"
    done
    
    echo -e "\n===== GROUPES ====="
    printf "%-20s %-15s %-30s\n" "NOM" "GID" "MEMBRES"
    
    # Afficher les groupes principaux
    cat /etc/group | grep -v "^#" | \
    while IFS=: read -r groupname _ gid members; do
        if [ -n "$members" ] || [ "$gid" -ge 1000 ]; then
            printf "%-20s %-15s %-30s\n" "$groupname" "$gid" "$members"
        fi
    done
}

# Créer un nouvel utilisateur
create_user() {
    local username="$1"
    local password="$2"
    local homedir="$3"
    local shell="$4"
    local groups="$5"
    
    log "INFO" "Création de l'utilisateur: $username"
    
    # Vérifier si l'utilisateur existe déjà
    if id "$username" &>/dev/null; then
        log "ERROR" "L'utilisateur $username existe déjà"
        return 1
    fi
    
    # Créer l'utilisateur
    useradd -m -d "${homedir:-/home/$username}" -s "${shell:-/bin/bash}" "$username"
    
    # Définir le mot de passe
    echo "$username:$password" | chpasswd
    
    # Ajouter aux groupes si spécifié
    if [ -n "$groups" ]; then
        usermod -aG "$groups" "$username"
    fi
    
    log "INFO" "Utilisateur $username créé avec succès"
    return 0
}

# Supprimer un utilisateur
delete_user() {
    local username="$1"
    local keep_home="$2"  # "yes" ou "no"
    
    log "INFO" "Suppression de l'utilisateur: $username"
    
    # Vérifier si l'utilisateur existe
    if ! id "$username" &>/dev/null; then
        log "ERROR" "L'utilisateur $username n'existe pas"
        return 1
    fi
    
    # Supprimer l'utilisateur
    if [ "$keep_home" = "yes" ]; then
        userdel "$username"
    else
        userdel -r "$username"
    fi
    
    log "INFO" "Utilisateur $username supprimé avec succès"
    return 0
}

# Modifier le mot de passe d'un utilisateur
change_user_password() {
    local username="$1"
    local password="$2"
    
    log "INFO" "Modification du mot de passe pour: $username"
    
    # Vérifier si l'utilisateur existe
    if ! id "$username" &>/dev/null; then
        log "ERROR" "L'utilisateur $username n'existe pas"
        return 1
    fi
    
    # Changer le mot de passe
    echo "$username:$password" | chpasswd
    
    log "INFO" "Mot de passe modifié pour $username"
    return 0
}

# Gérer les groupes (créer/supprimer/ajouter membres)
manage_group() {
    local action="$1"
    local groupname="$2"
    local members="$3"  # Optionnel, pour ajouter des membres
    
    log "INFO" "Gestion du groupe $groupname: $action"
    
    case "$action" in
        create)
            groupadd "$groupname"
            ;;
        delete)
            groupdel "$groupname"
            ;;
        add_members)
            for user in $(echo "$members" | tr ',' ' '); do
                usermod -aG "$groupname" "$user"
            done
            ;;
        remove_members)
            for user in $(echo "$members" | tr ',' ' '); do
                gpasswd -d "$user" "$groupname"
            done
            ;;
        *)
            log "ERROR" "Action non reconnue: $action"
            return 1
            ;;
    esac
    
    log "INFO" "Action $action réussie pour le groupe $groupname"
    return 0
}

# ===== MODULE: SÉCURITÉ ET RÉSEAU (IPTABLES) =====

# Sauvegarder les règles iptables actuelles
backup_iptables() {
    log "INFO" "Sauvegarde des règles iptables..."
    
    mkdir -p "$(dirname "$IPTABLES_RULES")"
    iptables-save > "$IPTABLES_RULES"
    
    log "INFO" "Règles iptables sauvegardées dans $IPTABLES_RULES"
    return 0
}

# Restaurer les règles iptables
restore_iptables() {
    log "INFO" "Restauration des règles iptables..."
    
    if [ -f "$IPTABLES_RULES" ]; then
        iptables-restore < "$IPTABLES_RULES"
        log "INFO" "Règles iptables restaurées depuis $IPTABLES_RULES"
        return 0
    else
        log "ERROR" "Fichier de règles iptables non trouvé: $IPTABLES_RULES"
        return 1
    fi
}

# Afficher les règles iptables actuelles
list_iptables_rules() {
    log "INFO" "Listage des règles iptables..."
    
    echo -e "\n===== RÈGLES IPTABLES ====="
    echo -e "FILTER TABLE (INPUT, FORWARD, OUTPUT):"
    iptables -L -v -n
    
    echo -e "\nNAT TABLE:"
    iptables -t nat -L -v -n
    
    return 0
}

# Ajouter une règle iptables
add_iptables_rule() {
    local table="$1"    # filter, nat, mangle, raw
    local chain="$2"    # INPUT, OUTPUT, FORWARD, etc.
    local rule="$3"     # Reste de la règle (ex: -p tcp --dport 80 -j ACCEPT)
    
    log "INFO" "Ajout d'une règle iptables: $table $chain $rule"
    
    iptables -t "$table" -A "$chain" $rule
    
    if [ $? -eq 0 ]; then
        backup_iptables
        log "INFO" "Règle ajoutée avec succès"
        return 0
    else
        log "ERROR" "Échec de l'ajout de la règle"
        return 1
    fi
}

# Supprimer une règle iptables
delete_iptables_rule() {
    local table="$1"
    local chain="$2"
    local rule_num="$3"
    
    log "INFO" "Suppression de la règle iptables: $table $chain règle #$rule_num"
    
    iptables -t "$table" -D "$chain" "$rule_num"
    
    if [ $? -eq 0 ]; then
        backup_iptables
        log "INFO" "Règle supprimée avec succès"
        return 0
    else
        log "ERROR" "Échec de la suppression de la règle"
        return 1
    fi
}

# Configurer des règles iptables de base (sécurisées)
setup_basic_firewall() {
    log "INFO" "Configuration du pare-feu de base..."
    
    # Effacer toutes les règles existantes
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    
    # Politique par défaut
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # Autoriser les connexions établies et connexes
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
    # Autoriser le loopback
    iptables -A INPUT -i lo -j ACCEPT
    
    # Autoriser SSH (port 22)
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    # Autoriser HTTP/HTTPS (ports 80/443)
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    
    # Autoriser FTP (ports 20/21)
    iptables -A INPUT -p tcp --dport 20 -j ACCEPT
    iptables -A INPUT -p tcp --dport 21 -j ACCEPT
    
    # Autoriser les ports passifs FTP (si nécessaire)
    iptables -A INPUT -p tcp --dport 10000:10100 -j ACCEPT
    
    # Autoriser WireGuard VPN (port 51820/udp)
    iptables -A INPUT -p udp --dport 51820 -j ACCEPT
    
    # Autoriser ERPNext (ports 8000/8080 si nécessaire)
    iptables -A INPUT -p tcp --dport 8000 -j ACCEPT
    iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
    
    # Autoriser ICMP (ping)
    iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
    
    # Journaliser les paquets rejetés
    iptables -A INPUT -j LOG --log-prefix "IPTables-Dropped: " --log-level 4
    
    # Sauvegarder les règles
    backup_iptables
    
    log "INFO" "Pare-feu de base configuré avec succès"
    return 0
}

# ===== MODULE: GESTION VPN (WIREGUARD) =====

# Vérifier le statut du VPN
check_vpn_status() {
    log "INFO" "Vérification du statut VPN..."
    
    if systemctl is-active --quiet wg-quick@wg0; then
        echo "VPN WireGuard: ACTIF"
        wg show
    else
        echo "VPN WireGuard: INACTIF"
    fi
    
    return 0
}

# Générer une configuration client WireGuard
generate_wireguard_client() {
    local client_name="$1"
    local server_pubkey="$2"
    local server_endpoint="$3"
    local allowed_ips="$4"
    
    log "INFO" "Génération d'une configuration client WireGuard pour $client_name..."
    
    # Créer le répertoire pour les clients
    mkdir -p "/etc/wireguard/clients"
    
    # Générer les clés
    wg genkey | tee "/etc/wireguard/clients/${client_name}.key" | wg pubkey > "/etc/wireguard/clients/${client_name}.pub"
    
    # Récupérer les clés
    client_privkey=$(cat "/etc/wireguard/clients/${client_name}.key")
    client_pubkey=$(cat "/etc/wireguard/clients/${client_name}.pub")
    
    # Créer le fichier de configuration client
    cat > "/etc/wireguard/clients/${client_name}.conf" << EOF
[Interface]
PrivateKey = ${client_privkey}
Address = 10.0.0.2/24
DNS = 8.8.8.8, 8.8.4.4

[Peer]
PublicKey = ${server_pubkey}
Endpoint = ${server_endpoint}:51820
AllowedIPs = ${allowed_ips:-0.0.0.0/0}
PersistentKeepalive = 25
EOF
    
    # Ajouter le client au serveur
    wg set wg0 peer "$client_pubkey" allowed-ips "10.0.0.2/32"
    wg-quick save wg0
    
    log "INFO" "Configuration client WireGuard générée pour $client_name"
    echo "Configuration client sauvegardée dans /etc/wireguard/clients/${client_name}.conf"
    echo "Clé publique du client: $client_pubkey"
    
    return 0
}

# ===== MODULE: LOGS ET DIAGNOSTICS =====

# Afficher les logs du système
view_logs() {
    local log_file="$1"
    local lines="$2"
    local filter="$3"
    
    log "INFO" "Affichage des logs: $log_file (lignes: $lines, filtre: $filter)"
    
    if [ -f "$log_file" ]; then
        if [ -n "$filter" ]; then
            grep "$filter" "$log_file" | tail -n "$lines"
        else
            tail -n "$lines" "$log_file"
        fi
    else
        log "ERROR" "Fichier de log non trouvé: $log_file"
        return 1
    fi
    
    return 0
}

# Exécuter des diagnostics système
run_diagnostics() {
    log "INFO" "Exécution des diagnostics système..."
    
    echo -e "\n===== DIAGNOSTICS SYSTÈME ====="
    
    echo -e "\n== UTILISATION DISQUE =="
    df -h
    
    echo -e "\n== UTILISATION MÉMOIRE =="
    free -h
    
    echo -e "\n== CHARGE CPU =="
    uptime
    
    echo -e "\n== PROCESSUS LES PLUS GOURMANDS =="
    ps aux --sort=-%cpu | head -11
    
    echo -e "\n== CONNEXIONS RÉSEAU =="
    ss -tulpn
    
    echo -e "\n== VÉRIFICATION DES SERVICES CRITIQUES =="
    services=("docker" "nginx" "ssh" "mariadb" "wg-quick@wg0" "vsftpd")
    for service in "${services[@]}"; do
        systemctl is-active --quiet "$service"
        status=$?
        if [ $status -eq 0 ]; then
            echo "$service: OK"
        else
            echo "$service: PROBLÈME (code: $status)"
        fi
    done
    
    return 0
}

# ===== MODULE: HÉBERGEMENT WEB =====

# Créer un nouveau site web
create_website() {
    local site_name="$1"
    local document_root="$2"
    local server_name="$3"
    local enable_ssl="$4"  # "yes" ou "no"
    
    log "INFO" "Création du site web: $site_name"
    
    # Créer le répertoire du site
    mkdir -p "${document_root:-$WEB_ROOT/$site_name}"
    chown -R www-data:www-data "${document_root:-$WEB_ROOT/$site_name}"
    
    # Créer la configuration Nginx
    cat > "/etc/nginx/sites-available/$site_name" << EOF
server {
    listen 80;
    server_name ${server_name:-$site_name};
    
    root ${document_root:-$WEB_ROOT/$site_name};
    index index.html index.htm index.php;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # PHP configuration (if needed)
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
    }
    
    location ~ /\.ht {
        deny all;
    }
}
EOF
    
    # Activer le site
    ln -sf "/etc/nginx/sites-available/$site_name" "/etc/nginx/sites-enabled/"
    
    # Configurer SSL si demandé
    if [ "$enable_ssl" = "yes" ]; then
        # Utiliser Let's Encrypt si disponible, sinon générer un certificat auto-signé
        if command -v certbot &>/dev/null; then
            certbot --nginx -d "$server_name" --non-interactive --agree-tos --email "admin@example.com"
        else
            # Générer un certificat auto-signé
            mkdir -p "/etc/nginx/ssl/$site_name"
            openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                -keyout "/etc/nginx/ssl/$site_name/privkey.pem" \
                -out "/etc/nginx/ssl/$site_name/fullchain.pem" \
                -subj "/CN=$server_name"
            
            # Mettre à jour la configuration avec SSL
            cat > "/etc/nginx/sites-available/$site_name" << EOF
server {
    listen 80;
    server_name ${server_name:-$site_name};
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name ${server_name:-$site_name};
    
    ssl_certificate /etc/nginx/ssl/$site_name/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/$site_name/privkey.pem;
    
    root ${document_root:-$WEB_ROOT/$site_name};
    index index.html index.htm index.php;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # PHP configuration (if needed)
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
    }
    
    location ~ /\.ht {
        deny all;
    }
}
EOF
        fi
    fi
    
    # Vérifier la configuration Nginx
    nginx -t
    if [ $? -eq 0 ]; then
        # Recharger Nginx
        systemctl reload nginx
        log "INFO" "Site web $site_name créé avec succès"
        return 0
    else
        log "ERROR" "Configuration Nginx invalide pour $site_name"
        return 1
    fi
}

# Supprimer un site web
delete_website() {
    local site_name="$1"
    local delete_files="$2"  # "yes" ou "no"
    
    log "INFO" "Suppression du site web: $site_name"
    
    # Désactiver le site
    rm -f "/etc/nginx/sites-enabled/$site_name"
    
    # Supprimer la configuration
    rm -f "/etc/nginx/sites-available/$site_name"
    
    # Supprimer les certificats SSL si présents
    rm -rf "/etc/nginx/ssl/$site_name"
    
    # Supprimer les fichiers du site si demandé
    if [ "$delete_files" = "yes" ]; then
        rm -rf "$WEB_ROOT/$site_name"
    fi
    
    # Recharger Nginx
    systemctl reload nginx
    
    log "INFO" "Site web $site_name supprimé avec succès"
    return 0
}

# ===== MODULE: SNAPSHOTS ET SAUVEGARDES =====

# Créer un snapshot du système
create_snapshot() {
    local snapshot_name="$1"
    local include_databases="$2"  # "yes" ou "no"
    local encrypt="$3"            # "yes" ou "no"
    local encryption_password="$4"  # Optionnel
    
    log "INFO" "Création d'un snapshot: $snapshot_name"
    
    # Créer le répertoire pour le snapshot
    snapshot_dir="$SNAPSHOT_DIR/$snapshot_name-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$snapshot_dir"
    
    # Sauvegarder les fichiers de configuration
    mkdir -p "$snapshot_dir/etc"
    cp -a /etc/nginx "$snapshot_dir/etc/"
    cp -a /etc/ssh "$snapshot_dir/etc/"
    cp -a /etc/wireguard "$snapshot_dir/etc/"
    cp -a /etc/iptables "$snapshot_dir/etc/"
    cp -a /etc/vsftpd.conf "$snapshot_dir/etc/" 2>/dev/null
    
    # Sauvegarder les volumes Docker (ERPNext)
    if command -v docker &>/dev/null; then
        mkdir -p "$snapshot_dir/docker"
        docker_volumes=$(docker volume ls -q)
        for volume in $docker_volumes; do
            # Créer un tar des volumes Docker
            docker run --rm --volumes-from $(docker ps -q) -v "$snapshot_dir/docker:/backup" busybox tar cvf "/backup/$volume.tar" "/var/lib/docker/volumes/$volume"
        done
    fi
    
    # Sauvegarder les bases de données si demandé
    if [ "$include_databases" = "yes" ]; then
        mkdir -p "$snapshot_dir/databases"
        
        # MariaDB/MySQL
        if command -v mysqldump &>/dev/null; then
            databases=$(mysql -e "SHOW DATABASES;" | grep -Ev "(Database|information_schema|performance_schema)")
            for db in $databases; do
                mysqldump --single-transaction --quick --lock-tables=false "$db" > "$snapshot_dir/databases/$db.sql"
            done
        fi
        
        # PostgreSQL
        if command -v pg_dump &>/dev/null; then
            if [ -d "/var/lib/postgresql" ]; then
                su - postgres -c "pg_dumpall" > "$snapshot_dir/databases/postgres_all.sql"
            fi
        fi
    fi
    
    # Créer une archive du snapshot
    snapshot_archive="$SNAPSHOT_DIR/$snapshot_name-$(date +%Y%m%d-%H%M%S).tar.gz"
    tar -czf "$snapshot_archive" -C "$SNAPSHOT_DIR" "$(basename "$snapshot_dir")"
    
    # Chiffrer l'archive si demandé
    if [ "$encrypt" = "yes" ] && [ -n "$encryption_password" ]; then
        openssl enc -aes-256-cbc -salt -in "$snapshot_archive" -out "${snapshot_archive}.enc" -k "$encryption_password"
        rm "$snapshot_archive"
        snapshot_archive="${snapshot_archive}.enc"
    fi
    
    # Nettoyer le répertoire temporaire
    rm -rf "$snapshot_dir"
    
    log "INFO" "Snapshot créé avec succès: $snapshot_archive"
    echo "Snapshot créé: $snapshot_archive"
    return 0
}

# Restaurer un snapshot
restore_snapshot() {
    local snapshot_file="$1"
    local restore_databases="$2"  # "yes" ou "no"
    local encryption_password="$3"  # Optionnel, pour les snapshots chiffrés
    
    log "INFO" "Restauration du snapshot: $snapshot_file"
    
    # Vérifier si le fichier existe
    if [ ! -f "$snapshot_file" ]; then
        log "ERROR" "Fichier de snapshot non trouvé: $snapshot_file"
        return 1
    fi
    
    # Créer un répertoire temporaire pour l'extraction
    temp_dir=$(mktemp -d)
    
    # Déchiffrer si nécessaire
    if [[ "$snapshot_file" == *.enc ]]; then
        if [ -z "$encryption_password" ]; then
            log "ERROR" "Mot de passe requis pour déchiffrer le snapshot"
            return 1
        fi
        
        decrypted_file="${temp_dir}/snapshot.tar.gz"
        openssl enc -aes-256-cbc -d -in "$snapshot_file" -out "$decrypted_file" -k "$encryption_password"
        if [ $? -ne 0 ]; then
            log "ERROR" "Échec du déchiffrement du snapshot"
            rm -rf "$temp_dir"
            return 1
        fi
        snapshot_file="$decrypted_file"
    fi
    
    # Extraire l'archive
    tar -xzf "$snapshot_file" -C "$temp_dir"
    
    # Trouver le répertoire du snapshot
    snapshot_dir=$(find "$temp_dir" -type d -name "*-*" | head -1)
    
    if [ -z "$snapshot_dir" ]; then
        log "ERROR" "Structure de snapshot invalide"
        rm -rf "$temp_dir"
        return 1
    fi
    
    # Restaurer les fichiers de configuration
    if [ -d "$snapshot_dir/etc/nginx" ]; then
        cp -a "$snapshot_dir/etc/nginx" /etc/
    fi
    
    if [ -d "$snapshot_dir/etc/ssh" ]; then
        cp -a "$snapshot_dir/etc/ssh" /etc/
    fi
    
    if [ -d "$snapshot_dir/etc/wireguard" ]; then
        cp -a "$snapshot_dir/etc/wireguard" /etc/
    fi
    
    if [ -d "$snapshot_dir/etc/iptables" ]; then
        cp -a "$snapshot_dir/etc/iptables" /etc/
        restore_iptables
    fi
    
    if [ -f "$snapshot_dir/etc/vsftpd.conf" ]; then
        cp -a "$snapshot_dir/etc/vsftpd.conf" /etc/
    fi
    
    # Restaurer les volumes Docker
    if [ -d "$snapshot_dir/docker" ] && command -v docker &>/dev/null; then
        for tar_file in "$snapshot_dir/docker"/*.tar; do
            if [ -f "$tar_file" ]; then
                volume_name=$(basename "$tar_file" .tar)
                # Créer le volume s'il n'existe pas
                docker volume inspect "$volume_name" >/dev/null 2>&1 || docker volume create "$volume_name"
                # Restaurer les données
                docker run --rm -v "$volume_name:/volume" -v "$(dirname "$tar_file"):/backup" busybox tar xf "/backup/$(basename "$tar_file")" -C /volume
            fi
        done
    fi
    
    # Restaurer les bases de données si demandé
    if [ "$restore_databases" = "yes" ] && [ -d "$snapshot_dir/databases" ]; then
        # MariaDB/MySQL
        if command -v mysql &>/dev/null; then
            for sql_file in "$snapshot_dir/databases"/*.sql; do
                if [[ "$sql_file" != *"postgres"* ]]; then
                    db_name=$(basename "$sql_file" .sql)
                    mysql -e "CREATE DATABASE IF NOT EXISTS $db_name;"
                    mysql "$db_name" < "$sql_file"
                fi
            done
        fi
        
        # PostgreSQL
        if command -v psql &>/dev/null && [ -f "$snapshot_dir/databases/postgres_all.sql" ]; then
            su - postgres -c "psql -f $snapshot_dir/databases/postgres_all.sql postgres"
        fi
    fi
    
    # Redémarrer les services
    systemctl restart nginx
    systemctl restart ssh
    
    if systemctl list-unit-files | grep -q "wg-quick@"; then
        systemctl restart wg-quick@wg0
    fi
    
    if systemctl list-unit-files | grep -q "vsftpd"; then
        systemctl restart vsftpd
    fi
    
    if command -v docker &>/dev/null; then
        systemctl restart docker
    fi
    
    # Nettoyer
    rm -rf "$temp_dir"
    
    log "INFO" "Snapshot restauré avec succès"
    echo "Snapshot restauré avec succès"
    return 0
}

# Envoyer un snapshot vers un serveur distant
upload_snapshot() {
    local snapshot_file="$1"
    local remote_server="$2"
    local remote_user="$3"
    local remote_path="$4"
    local ssh_key="$5"  # Optionnel
    
    log "INFO" "Envoi du snapshot vers le serveur distant: $remote_server"
    
    # Vérifier si le fichier existe
    if [ ! -f "$snapshot_file" ]; then
        log "ERROR" "Fichier de snapshot non trouvé: $snapshot_file"
        return 1
    fi
    
    # Construire la commande SCP
    scp_cmd="scp"
    
    if [ -n "$ssh_key" ]; then
        scp_cmd="$scp_cmd -i $ssh_key"
    fi
    
    # Exécuter la commande
    $scp_cmd "$snapshot_file" "${remote_user}@${remote_server}:${remote_path}"
    
    if [ $? -eq 0 ]; then
        log "INFO" "Snapshot envoyé avec succès vers $remote_server:$remote_path"
        echo "Snapshot envoyé avec succès"
        return 0
    else
        log "ERROR" "Échec de l'envoi du snapshot vers $remote_server"
        return 1
    fi
}

# ===== MENU INTERACTIF =====

show_menu() {
    clear
    echo "===== EcoManage - Système de Gestion Linux Centralisé ====="
    echo "1. Tableau de bord (Résumé système)"
    echo "2. Gestion des services"
    echo "3. Gestion des utilisateurs et groupes"
    echo "4. Sécurité et réseau (iptables)"
    echo "5. Logs et diagnostics"
    echo "6. Hébergement web"
    echo "7. Snapshots et sauvegardes"
    echo "0. Quitter"
    echo "========================================================"
    echo -n "Choisissez une option: "
}

service_menu() {
    clear
    echo "===== GESTION DES SERVICES ====="
    echo "1. Lister tous les services"
    echo "2. Démarrer un service"
    echo "3. Arrêter un service"
    echo "4. Redémarrer un service"
    echo "5. Afficher le statut d'un service"
    echo "6. Activer un service au démarrage"
    echo "7. Désactiver un service au démarrage"
    echo "8. Afficher les logs d'un service"
    echo "9. Éditer la configuration d'un service"
    echo "0. Retour au menu principal"
    echo "==============================="
    echo -n "Choisissez une option: "
}

user_menu() {
    clear
    echo "===== GESTION DES UTILISATEURS ET GROUPES ====="
    echo "1. Lister tous les utilisateurs et groupes"
    echo "2. Créer un nouvel utilisateur"
    echo "3. Supprimer un utilisateur"
    echo "4. Modifier le mot de passe d'un utilisateur"
    echo "5. Créer un nouveau groupe"
    echo "6. Supprimer un groupe"
    echo "7. Ajouter des utilisateurs à un groupe"
    echo "8. Supprimer des utilisateurs d'un groupe"
    echo "0. Retour au menu principal"
    echo "============================================="
    echo -n "Choisissez une option: "
}

security_menu() {
    clear
    echo "===== SÉCURITÉ ET RÉSEAU (IPTABLES) ====="
    echo "1. Afficher les règles iptables"
    echo "2. Ajouter une règle iptables"
    echo "3. Supprimer une règle iptables"
    echo "4. Configurer un pare-feu de base"
    echo "5. Sauvegarder les règles iptables"
    echo "6. Restaurer les règles iptables"
    echo "7. Gestion VPN (WireGuard)"
    echo "0. Retour au menu principal"
    echo "======================================="
    echo -n "Choisissez une option: "
}

logs_menu() {
    clear
    echo "===== LOGS ET DIAGNOSTICS ====="
    echo "1. Afficher les logs système (syslog)"
    echo "2. Afficher les logs d'authentification"
    echo "3. Afficher les logs nginx"
    echo "4. Afficher les logs FTP"
    echo "5. Afficher les logs Docker"
    echo "6. Exécuter des diagnostics système"
    echo "0. Retour au menu principal"
    echo "==============================="
    echo -n "Choisissez une option: "
}

web_menu() {
    clear
    echo "===== HÉBERGEMENT WEB ====="
    echo "1. Lister les sites web"
    echo "2. Créer un nouveau site web"
    echo "3. Supprimer un site web"
    echo "4. Activer/Désactiver un site web"
    echo "5. Configurer SSL pour un site"
    echo "0. Retour au menu principal"
    echo "==========================="
    echo -n "Choisissez une option: "
}

snapshot_menu() {
    clear
    echo "===== SNAPSHOTS ET SAUVEGARDES ====="
    echo "1. Lister les snapshots disponibles"
    echo "2. Créer un nouveau snapshot"
    echo "3. Restaurer un snapshot"
    echo "4. Envoyer un snapshot vers un serveur distant"
    echo "5. Configurer des sauvegardes automatiques"
    echo "0. Retour au menu principal"
    echo "==================================="
    echo -n "Choisissez une option: "
}

vpn_menu() {
    clear
    echo "===== GESTION VPN (WIREGUARD) ====="
    echo "1. Vérifier le statut du VPN"
    echo "2. Démarrer/Arrêter le VPN"
    echo "3. Générer une configuration client"
    echo "4. Lister les clients VPN"
    echo "5. Révoquer un client VPN"
    echo "0. Retour au menu de sécurité"
    echo "=================================="
    echo -n "Choisissez une option: "
}

# ===== FONCTION PRINCIPALE =====

main() {
    # Vérifier les privilèges root
    check_root
    
    # Créer les répertoires nécessaires
    setup_directories
    
    # Vérifier et installer les dépendances
    check_dependencies || {
        log "ERROR" "Impossible de continuer sans les dépendances requises"
        exit 1
    }
    
    # Menu principal
    while true; do
        show_menu
        read -r choice
        
        case $choice in
            1)
                # Tableau de bord
                get_system_summary
                read -p "Appuyez sur Entrée pour continuer..."
                ;;
            2)
                # Gestion des services
                while true; do
                    service_menu
                    read -r service_choice
                    
                    case $service_choice in
                        1)
                            list_services
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        2)
                            read -p "Nom du service à démarrer: " service_name
                            manage_service "$service_name" "start"
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        3)
                            read -p "Nom du service à arrêter: " service_name
                            manage_service "$service_name" "stop"
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        4)
                            read -p "Nom du service à redémarrer: " service_name
                            manage_service "$service_name" "restart"
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        5)
                            read -p "Nom du service à vérifier: " service_name
                            manage_service "$service_name" "status"
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        6)
                            read -p "Nom du service à activer au démarrage: " service_name
                            manage_service "$service_name" "enable"
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        7)
                            read -p "Nom du service à désactiver au démarrage: " service_name
                            manage_service "$service_name" "disable"
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        8)
                            read -p "Nom du service pour afficher les logs: " service_name
                            manage_service "$service_name" "logs"
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        9)
                            read -p "Nom du service pour éditer la configuration: " service_name
                            edit_service_config "$service_name"
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        0)
                            break
                            ;;
                        *)
                            echo "Option invalide"
                            sleep 1
                            ;;
                    esac
                done
                ;;
            3)
                # Gestion des utilisateurs et groupes
                while true; do
                    user_menu
                    read -r user_choice
                    
                    case $user_choice in
                        1)
                            list_users
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        2)
                            read -p "Nom d'utilisateur: " username
                            read -s -p "Mot de passe: " password
                            echo
                            read -p "Répertoire personnel [/home/$username]: " homedir
                            homedir=${homedir:-/home/$username}
                            read -p "Shell [/bin/bash]: " shell
                            shell=${shell:-/bin/bash}
                            read -p "Groupes (séparés par des virgules): " groups
                            create_user "$username" "$password" "$homedir" "$shell" "$groups"
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        3)
                            read -p "Nom d'utilisateur à supprimer: " username
                            read -p "Conserver le répertoire personnel? (yes/no) [no]: " keep_home
                            keep_home=${keep_home:-no}
                            delete_user "$username" "$keep_home"
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        4)
                            read -p "Nom d'utilisateur: " username
                            read -s -p "Nouveau mot de passe: " password
                            echo
                            change_user_password "$username" "$password"
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        5)
                            read -p "Nom du groupe à créer: " groupname
                            manage_group "create" "$groupname"
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        6)
                            read -p "Nom du groupe à supprimer: " groupname
                            manage_group "delete" "$groupname"
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        7)
                            read -p "Nom du groupe: " groupname
                            read -p "Utilisateurs à ajouter (séparés par des virgules): " members
                            manage_group "add_members" "$groupname" "$members"
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        8)
                            read -p "Nom du groupe: " groupname
                            read -p "Utilisateurs à supprimer (séparés par des virgules): " members
                            manage_group "remove_members" "$groupname" "$members"
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        0)
                            break
                            ;;
                        *)
                            echo "Option invalide"
                            sleep 1
                            ;;
                    esac
                done
                ;;
            4)
                # Sécurité et réseau
                while true; do
                    security_menu
                    read -r security_choice
                    
                    case $security_choice in
                        1)
                            list_iptables_rules
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        2)
                            read -p "Table (filter, nat, mangle, raw) [filter]: " table
                            table=${table:-filter}
                            read -p "Chaîne (INPUT, OUTPUT, FORWARD, etc.) [INPUT]: " chain
                            chain=${chain:-INPUT}
                            read -p "Règle (ex: -p tcp --dport 80 -j ACCEPT): " rule
                            add_iptables_rule "$table" "$chain" "$rule"
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        3)
                            read -p "Table (filter, nat, mangle, raw) [filter]: " table
                            table=${table:-filter}
                            read -p "Chaîne (INPUT, OUTPUT, FORWARD, etc.) [INPUT]: " chain
                            chain=${chain:-INPUT}
                            read -p "Numéro de règle à supprimer: " rule_num
                            delete_iptables_rule "$table" "$chain" "$rule_num"
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        4)
                            read -p "Cette action va réinitialiser toutes les règles existantes. Continuer? (yes/no) [no]: " confirm
                            confirm=${confirm:-no}
                            if [ "$confirm" = "yes" ]; then
                                setup_basic_firewall
                            fi
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        5)
                            backup_iptables
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        6)
                            restore_iptables
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        7)
                            # Sous-menu VPN
                            while true; do
                                vpn_menu
                                read -r vpn_choice
                                
                                case $vpn_choice in
                                    1)
                                        check_vpn_status
                                        read -p "Appuyez sur Entrée pour continuer..."
                                        ;;
                                    2)
                                        if systemctl is-active --quiet wg-quick@wg0; then
                                            systemctl stop wg-quick@wg0
                                            echo "VPN arrêté"
                                        else
                                            systemctl start wg-quick@wg0
                                            echo "VPN démarré"
                                        fi
                                        read -p "Appuyez sur Entrée pour continuer..."
                                        ;;
                                    3)
                                        read -p "Nom du client: " client_name
                                        read -p "Clé publique du serveur: " server_pubkey
                                        read -p "Endpoint du serveur (IP ou domaine): " server_endpoint
                                        read -p "IPs autorisées [0.0.0.0/0]: " allowed_ips
                                        allowed_ips=${allowed_ips:-0.0.0.0/0}
                                        generate_wireguard_client "$client_name" "$server_pubkey" "$server_endpoint" "$allowed_ips"
                                        read -p "Appuyez sur Entrée pour continuer..."
                                        ;;
                                    4)
                                        echo "Clients VPN configurés:"
                                        ls -la /etc/wireguard/clients/ 2>/dev/null || echo "Aucun client trouvé"
                                        read -p "Appuyez sur Entrée pour continuer..."
                                        ;;
                                    5)
                                        read -p "Nom du client à révoquer: " client_name
                                        if [ -f "/etc/wireguard/clients/${client_name}.pub" ]; then
                                            client_pubkey=$(cat "/etc/wireguard/clients/${client_name}.pub")
                                            wg set wg0 peer "$client_pubkey" remove
                                            wg-quick save wg0
                                            rm -f "/etc/wireguard/clients/${client_name}.*"
                                            echo "Client $client_name révoqué"
                                        else
                                            echo "Client non trouvé"
                                        fi
                                        read -p "Appuyez sur Entrée pour continuer..."
                                        ;;
                                    0)
                                        break
                                        ;;
                                    *)
                                        echo "Option invalide"
                                        sleep 1
                                        ;;
                                esac
                            done
                            ;;
                        0)
                            break
                            ;;
                        *)
                            echo "Option invalide"
                            sleep 1
                            ;;
                    esac
                done
                ;;
            5)
                # Logs et diagnostics
                while true; do
                    logs_menu
                    read -r logs_choice
                    
                    case $logs_choice in
                        1)
                            read -p "Nombre de lignes [50]: " lines
                            lines=${lines:-50}
                            read -p "Filtre (optionnel): " filter
                            view_logs "/var/log/syslog" "$lines" "$filter"
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        2)
                            read -p "Nombre de lignes [50]: " lines
                            lines=${lines:-50}
                            read -p "Filtre (optionnel): " filter
                            view_logs "/var/log/auth.log" "$lines" "$filter"
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        3)
                            read -p "Nombre de lignes [50]: " lines
                            lines=${lines:-50}
                            read -p "Filtre (optionnel): " filter
                            view_logs "/var/log/nginx/error.log" "$lines" "$filter"
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        4)
                            read -p "Nombre de lignes [50]: " lines
                            lines=${lines:-50}
                            read -p "Filtre (optionnel): " filter
                            view_logs "/var/log/vsftpd.log" "$lines" "$filter"
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        5)
                            read -p "Nombre de lignes [50]: " lines
                            lines=${lines:-50}
                            docker logs $(docker ps -q --filter "name=erpnext") | tail -n "$lines"
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        6)
                            run_diagnostics
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        0)
                            break
                            ;;
                        *)
                            echo "Option invalide"
                            sleep 1
                            ;;
                    esac
                done
                ;;
            6)
                # Hébergement web
                while true; do
                    web_menu
                    read -r web_choice
                    
                    case $web_choice in
                        1)
                            echo "Sites web configurés:"
                            ls -la /etc/nginx/sites-available/
                            echo -e "\nSites web activés:"
                            ls -la /etc/nginx/sites-enabled/
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        2)
                            read -p "Nom du site: " site_name
                            read -p "Répertoire racine [/var/www/$site_name]: " document_root
                            document_root=${document_root:-/var/www/$site_name}
                            read -p "Nom de serveur (domaine): " server_name
                            read -p "Activer SSL? (yes/no) [no]: " enable_ssl
                            enable_ssl=${enable_ssl:-no}
                            create_website "$site_name" "$document_root" "$server_name" "$enable_ssl"
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        3)
                            read -p "Nom du site à supprimer: " site_name
                            read -p "Supprimer les fichiers? (yes/no) [no]: " delete_files
                            delete_files=${delete_files:-no}
                            delete_website "$site_name" "$delete_files"
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        4)
                            read -p "Nom du site: " site_name
                            if [ -f "/etc/nginx/sites-enabled/$site_name" ]; then
                                rm -f "/etc/nginx/sites-enabled/$site_name"
                                echo "Site désactivé"
                            else
                                ln -sf "/etc/nginx/sites-available/$site_name" "/etc/nginx/sites-enabled/"
                                echo "Site activé"
                            fi
                            systemctl reload nginx
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        5)
                            read -p "Nom du site: " site_name
                            read -p "Nom de serveur (domaine): " server_name
                            if command -v certbot &>/dev/null; then
                                certbot --nginx -d "$server_name" --non-interactive --agree-tos --email "admin@example.com"
                            else
                                echo "Certbot non installé. Installation..."
                                apt-get update
                                apt-get install -y certbot python3-certbot-nginx
                                certbot --nginx -d "$server_name" --non-interactive --agree-tos --email "admin@example.com"
                            fi
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        0)
                            break
                            ;;
                        *)
                            echo "Option invalide"
                            sleep 1
                            ;;
                    esac
                done
                ;;
            7)
                # Snapshots et sauvegardes
                while true; do
                    snapshot_menu
                    read -r snapshot_choice
                    
                    case $snapshot_choice in
                        1)
                            echo "Snapshots disponibles:"
                            ls -la "$SNAPSHOT_DIR"
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        2)
                            read -p "Nom du snapshot: " snapshot_name
                            read -p "Inclure les bases de données? (yes/no) [yes]: " include_databases
                            include_databases=${include_databases:-yes}
                            read -p "Chiffrer le snapshot? (yes/no) [no]: " encrypt
                            encrypt=${encrypt:-no}
                            if [ "$encrypt" = "yes" ]; then
                                read -s -p "Mot de passe de chiffrement: " encryption_password
                                echo
                            else
                                encryption_password=""
                            fi
                            create_snapshot "$snapshot_name" "$include_databases" "$encrypt" "$encryption_password"
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        3)
                            echo "Snapshots disponibles:"
                            ls -la "$SNAPSHOT_DIR"
                            read -p "Chemin complet du snapshot à restaurer: " snapshot_file
                            read -p "Restaurer les bases de données? (yes/no) [yes]: " restore_databases
                            restore_databases=${restore_databases:-yes}
                            if [[ "$snapshot_file" == *.enc ]]; then
                                read -s -p "Mot de passe de déchiffrement: " encryption_password
                                echo
                            else
                                encryption_password=""
                            fi
                            restore_snapshot "$snapshot_file" "$restore_databases" "$encryption_password"
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        4)
                            echo "Snapshots disponibles:"
                            ls -la "$SNAPSHOT_DIR"
                            read -p "Chemin complet du snapshot à envoyer: " snapshot_file
                            read -p "Serveur distant (IP ou domaine): " remote_server
                            read -p "Utilisateur distant: " remote_user
                            read -p "Chemin distant: " remote_path
                            read -p "Utiliser une clé SSH? (yes/no) [no]: " use_key
                            use_key=${use_key:-no}
                            if [ "$use_key" = "yes" ]; then
                                read -p "Chemin de la clé SSH: " ssh_key
                            else
                                ssh_key=""
                            fi
                            upload_snapshot "$snapshot_file" "$remote_server" "$remote_user" "$remote_path" "$ssh_key"
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        5)
                            echo "Configuration des sauvegardes automatiques..."
                            read -p "Fréquence (daily, weekly, monthly) [daily]: " frequency
                            frequency=${frequency:-daily}
                            read -p "Heure d'exécution (format 24h, ex: 02:00) [03:00]: " time
                            time=${time:-03:00}
                            hour=$(echo "$time" | cut -d':' -f1)
                            minute=$(echo "$time" | cut -d':' -f2)
                            read -p "Nom du snapshot: " snapshot_name
                            read -p "Inclure les bases de données? (yes/no) [yes]: " include_databases
                            include_databases=${include_databases:-yes}
                            read -p "Chiffrer le snapshot? (yes/no) [no]: " encrypt
                            encrypt=${encrypt:-no}
                            if [ "$encrypt" = "yes" ]; then
                                read -s -p "Mot de passe de chiffrement: " encryption_password
                                echo
                                # Stocker le mot de passe de manière sécurisée
                                echo "$encryption_password" > "$CONFIG_DIR/backup_password"
                                chmod 600 "$CONFIG_DIR/backup_password"
                            fi
                            
                            # Créer le script de sauvegarde
                            cat > "$CONFIG_DIR/auto_backup.sh" << EOF
#!/bin/bash
source $(dirname "$0")/../ecomanage.sh
if [ "$encrypt" = "yes" ]; then
    encryption_password=\$(cat "$CONFIG_DIR/backup_password")
    create_snapshot "$snapshot_name" "$include_databases" "$encrypt" "\$encryption_password"
else
    create_snapshot "$snapshot_name" "$include_databases" "no" ""
fi
EOF
                            chmod +x "$CONFIG_DIR/auto_backup.sh"
                            
                            # Configurer le cron
                            case "$frequency" in
                                daily)
                                    cron_entry="$minute $hour * * * $CONFIG_DIR/auto_backup.sh > /var/log/ecomanage_backup.log 2>&1"
                                    ;;
                                weekly)
                                    cron_entry="$minute $hour * * 0 $CONFIG_DIR/auto_backup.sh > /var/log/ecomanage_backup.log 2>&1"
                                    ;;
                                monthly)
                                    cron_entry="$minute $hour 1 * * $CONFIG_DIR/auto_backup.sh > /var/log/ecomanage_backup.log 2>&1"
                                    ;;
                            esac
                            
                            # Ajouter au crontab
                            (crontab -l 2>/dev/null | grep -v "auto_backup.sh"; echo "$cron_entry") | crontab -
                            
                            echo "Sauvegarde automatique configurée: $frequency à $time"
                            read -p "Appuyez sur Entrée pour continuer..."
                            ;;
                        0)
                            break
                            ;;
                        *)
                            echo "Option invalide"
                            sleep 1
                            ;;
                    esac
                done
                ;;
            0)
                echo "Au revoir!"
                exit 0
                ;;
            *)
                echo "Option invalide"
                sleep 1
                ;;
        esac
    done
}

# Exécuter la fonction principale si le script est exécuté directement
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi

