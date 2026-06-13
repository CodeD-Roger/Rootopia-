#!/bin/bash
export PATH=$PATH:/usr/sbin:/sbin
# EcoManage - Système de Gestion Linux Centralisé
# Script principal pour la gestion des services, utilisateurs, sécurité et sauvegardes

# Variables globales
VERSION="2.1.0"
PROG="rootopia"
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")"
LOG_FILE="/var/log/ecomanage.log"
SNAPSHOT_DIR="/opt/ecomanage/snapshots"
CONFIG_DIR="/opt/ecomanage/config"
WEB_ROOT="/var/www"
IPTABLES_RULES="/etc/iptables/rules.v4"
# Email utilisé par certbot (surchargé par $ROOTOPIA_ADMIN_EMAIL)
ADMIN_EMAIL="${ROOTOPIA_ADMIN_EMAIL:-admin@example.com}"

# Drapeaux globaux (modifiables via les options de la CLI)
ASSUME_YES=0   # -y/--yes : ne pas demander de confirmation
QUIET=0        # -q/--quiet : ne pas afficher les logs INFO en console
DRY_RUN=0      # --dry-run : afficher les actions sans les exécuter

# Demander une confirmation (auto-validée avec -y/--yes ou en mode non-TTY+yes)
# Usage: confirm "Message ?" && action
confirm() {
    local prompt="${1:-Confirmer ?}"
    if [ "$ASSUME_YES" -eq 1 ]; then
        return 0
    fi
    # Pas de terminal interactif et pas de --yes : on refuse par sécurité
    if [ ! -t 0 ]; then
        log "ERROR" "Confirmation requise pour : $prompt (utilisez -y/--yes en non-interactif)"
        return 1
    fi
    local answer
    read -r -p "$prompt (yes/no) [no]: " answer
    [ "$answer" = "yes" ] || [ "$answer" = "y" ]
}

# Valider un nom "sûr" (utilisateur, groupe, site, snapshot) :
# uniquement lettres, chiffres, point, tiret et underscore — empêche l'injection de chemin.
valid_name() {
    [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]] && [[ "$1" != "."* ]]
}

# Lire un secret sans l'afficher (depuis le terminal). Renvoie la valeur sur stdout.
read_secret() {
    local prompt="${1:-Mot de passe: }" secret
    read -r -s -p "$prompt" secret </dev/tty
    echo >&2
    printf '%s' "$secret"
}

# Résout un mot de passe pour la CLI sans l'exposer dans `ps`.
# Priorité : --password-stdin (lit une ligne sur stdin) > prompt masqué (si TTY) > --password.
# $1 = valeur de --password ; $2 = flag stdin (1/0) ; $3 = libellé du prompt.
# Émet le secret sur stdout (les messages vont sur stderr). Renvoie 1 si impossible.
resolve_secret() {
    local provided="$1" from_stdin="$2" prompt="${3:-Mot de passe: }" s
    if [ "$from_stdin" -eq 1 ]; then
        IFS= read -r s
        printf '%s' "$s"
        return 0
    fi
    if [ -t 0 ] && [ -z "$provided" ]; then
        read_secret "$prompt"
        return 0
    fi
    if [ -n "$provided" ]; then
        log "WARN" "Mot de passe en clair sur la ligne de commande (visible dans 'ps') — préférez --password-stdin" >&2
        printf '%s' "$provided"
        return 0
    fi
    return 1
}

# Fonction pour journaliser les actions
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    { echo "[$timestamp] [$level] $message" >> "$LOG_FILE"; } 2>/dev/null

    # Afficher également dans la console si ce n'est pas silencieux.
    # En mode --quiet, on masque uniquement les messages INFO (on garde WARN/ERROR).
    if [ "$3" != "silent" ]; then
        if [ "$QUIET" -eq 1 ] && [ "$level" = "INFO" ]; then
            return 0
        fi
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

    if ! confirm "Installer les paquets manquants (${missing_commands[*]}) ?"; then
      log "ERROR" "Installation refusée — dépendances manquantes"
      return 1
    fi

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
    public_ip=$(curl -s --connect-timeout 3 --max-time 5 https://api.ipify.org)
    [ -z "$public_ip" ] && public_ip="(indisponible)"
    
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

    # Valider le nom (évite l'injection et les noms invalides)
    if ! valid_name "$username"; then
        log "ERROR" "Nom d'utilisateur invalide: '$username'"
        return 1
    fi

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

    if ! valid_name "$groupname"; then
        log "ERROR" "Nom de groupe invalide: '$groupname'"
        return 1
    fi

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
    local client_address="$5"   # optionnel : IP fixe du client (ex 10.0.0.5)

    log "INFO" "Génération d'une configuration client WireGuard pour $client_name..."

    if ! valid_name "$client_name"; then
        log "ERROR" "Nom de client invalide: '$client_name'"
        return 1
    fi

    # Créer le répertoire pour les clients
    mkdir -p "/etc/wireguard/clients"

    # Empêcher l'écrasement d'un client existant
    if [ -f "/etc/wireguard/clients/${client_name}.conf" ]; then
        log "ERROR" "Le client $client_name existe déjà"
        return 1
    fi

    # Allouer une IP libre dans 10.0.0.0/24 si non fournie
    local subnet="10.0.0"
    local client_ip="$client_address"
    if [ -z "$client_ip" ]; then
        local last=1   # .1 = serveur
        local f ip n
        for f in /etc/wireguard/clients/*.conf; do
            [ -e "$f" ] || continue
            ip=$(grep -E '^Address' "$f" | grep -oE '10\.0\.0\.[0-9]+' | head -1)
            n="${ip##*.}"
            if [ -n "$n" ] && [ "$n" -gt "$last" ]; then last="$n"; fi
        done
        client_ip="${subnet}.$((last + 1))"
    fi

    # Générer les clés
    wg genkey | tee "/etc/wireguard/clients/${client_name}.key" | wg pubkey > "/etc/wireguard/clients/${client_name}.pub"
    chmod 600 "/etc/wireguard/clients/${client_name}.key"

    # Récupérer les clés
    client_privkey=$(cat "/etc/wireguard/clients/${client_name}.key")
    client_pubkey=$(cat "/etc/wireguard/clients/${client_name}.pub")

    # Créer le fichier de configuration client
    cat > "/etc/wireguard/clients/${client_name}.conf" << EOF
[Interface]
PrivateKey = ${client_privkey}
Address = ${client_ip}/24
DNS = 8.8.8.8, 8.8.4.4

[Peer]
PublicKey = ${server_pubkey}
Endpoint = ${server_endpoint}:51820
AllowedIPs = ${allowed_ips:-0.0.0.0/0}
PersistentKeepalive = 25
EOF

    # Ajouter le client au serveur (avec son IP dédiée)
    wg set wg0 peer "$client_pubkey" allowed-ips "${client_ip}/32"
    wg-quick save wg0
    
    log "INFO" "Configuration client WireGuard générée pour $client_name"
    echo "Configuration client sauvegardée dans /etc/wireguard/clients/${client_name}.conf"
    echo "Adresse VPN attribuée: ${client_ip}/24"
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

    # Source des logs : fichier si présent, sinon bascule sur journalctl
    # (systèmes journald-only comme RHEL/Fedora n'ont pas /var/log/syslog).
    local -a source_cmd
    if [ -f "$log_file" ]; then
        source_cmd=(cat "$log_file")
    elif command -v journalctl &>/dev/null; then
        log "WARN" "Fichier $log_file introuvable — bascule sur journalctl"
        case "$log_file" in
            *auth.log) source_cmd=(journalctl -u ssh -u sshd --no-pager) ;;
            *nginx*)   source_cmd=(journalctl -u nginx --no-pager) ;;
            *vsftpd*)  source_cmd=(journalctl -u vsftpd --no-pager) ;;
            *)         source_cmd=(journalctl --no-pager) ;;
        esac
    else
        log "ERROR" "Source de logs introuvable: $log_file (et journalctl absent)"
        return 1
    fi

    if [ -n "$filter" ]; then
        "${source_cmd[@]}" 2>/dev/null | grep "$filter" | tail -n "$lines"
    else
        "${source_cmd[@]}" 2>/dev/null | tail -n "$lines"
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

    if ! valid_name "$site_name"; then
        log "ERROR" "Nom de site invalide: '$site_name'"
        return 1
    fi

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
            certbot --nginx -d "$server_name" --non-interactive --agree-tos --email "$ADMIN_EMAIL"
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

    if ! valid_name "$site_name"; then
        log "ERROR" "Nom de site invalide: '$site_name'"
        return 1
    fi

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

    if ! valid_name "$snapshot_name"; then
        log "ERROR" "Nom de snapshot invalide: '$snapshot_name'"
        return 1
    fi

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
    
    # Sauvegarder les volumes Docker (chaque volume monté individuellement en lecture seule)
    if command -v docker &>/dev/null; then
        mkdir -p "$snapshot_dir/docker"
        docker_volumes=$(docker volume ls -q)
        for volume in $docker_volumes; do
            log "INFO" "Sauvegarde du volume Docker: $volume" "silent"
            docker run --rm \
                -v "${volume}:/volume:ro" \
                -v "$snapshot_dir/docker:/backup" \
                busybox tar czf "/backup/${volume}.tar.gz" -C /volume . \
                || log "WARN" "Échec de la sauvegarde du volume $volume"
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
        for tar_file in "$snapshot_dir/docker"/*.tar.gz; do
            if [ -f "$tar_file" ]; then
                volume_name=$(basename "$tar_file" .tar.gz)
                # Créer le volume s'il n'existe pas
                docker volume inspect "$volume_name" >/dev/null 2>&1 || docker volume create "$volume_name"
                # Restaurer les données (contenu à la racine du volume)
                docker run --rm \
                    -v "${volume_name}:/volume" \
                    -v "$(dirname "$tar_file"):/backup" \
                    busybox tar xzf "/backup/$(basename "$tar_file")" -C /volume
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

# ===== MODULE: FAIL2BAN (ex ban2sec) =====

# S'assurer que fail2ban est installé
ensure_fail2ban() {
    if command -v fail2ban-client &>/dev/null; then
        return 0
    fi

    log "WARN" "fail2ban n'est pas installé"
    if [ "$DRY_RUN" -eq 1 ]; then
        log "INFO" "[dry-run] Installation de fail2ban ignorée"
        return 0
    fi

    log "INFO" "Installation de fail2ban..."
    if [ -f /etc/debian_version ]; then
        apt-get update && apt-get install -y fail2ban
    elif [ -f /etc/redhat-release ]; then
        yum install -y epel-release && yum install -y fail2ban
    elif [ -f /etc/alpine-release ]; then
        apk add --no-cache fail2ban
    else
        log "ERROR" "Distribution non reconnue. Installez fail2ban manuellement."
        return 1
    fi

    if ! command -v fail2ban-client &>/dev/null; then
        log "ERROR" "Échec de l'installation de fail2ban"
        return 1
    fi
    systemctl enable --now fail2ban 2>/dev/null
    log "INFO" "fail2ban installé et activé"
    return 0
}

# Statut global de fail2ban
fail2ban_status() {
    ensure_fail2ban || return 1
    log "INFO" "Statut fail2ban" "silent"

    echo -e "\n===== FAIL2BAN ====="
    if systemctl is-active --quiet fail2ban; then
        echo "Service: ACTIF"
    else
        echo "Service: INACTIF"
    fi

    echo -e "\n== Vue d'ensemble =="
    fail2ban-client status 2>/dev/null || echo "Impossible de récupérer le statut (service démarré ?)"
    return 0
}

# Lister les jails actives
fail2ban_list_jails() {
    ensure_fail2ban || return 1
    echo -e "\n===== JAILS FAIL2BAN ====="
    local jails
    jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed -E 's/^[^:]+:[ \t]*//' | tr ',' ' ')
    if [ -z "$jails" ]; then
        echo "Aucune jail active"
        return 0
    fi
    for jail in $jails; do
        echo -e "\n--- $jail ---"
        fail2ban-client status "$jail" 2>/dev/null
    done
    return 0
}

# Lister les IP actuellement bannies (toutes jails ou une jail précise)
fail2ban_banned() {
    local target_jail="$1"
    ensure_fail2ban || return 1

    echo -e "\n===== IP BANNIES ====="
    local jails
    if [ -n "$target_jail" ]; then
        jails="$target_jail"
    else
        jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed -E 's/^[^:]+:[ \t]*//' | tr ',' ' ')
    fi

    for jail in $jails; do
        local banned
        banned=$(fail2ban-client status "$jail" 2>/dev/null | grep "Banned IP list" | sed -E 's/^[^:]+:[ \t]*//')
        printf "%-20s %s\n" "$jail" "${banned:-(aucune)}"
    done
    return 0
}

# Bannir une IP dans une jail
fail2ban_ban() {
    local ip="$1"
    local jail="${2:-sshd}"

    if [ -z "$ip" ]; then
        log "ERROR" "IP requise pour le bannissement"
        return 1
    fi
    ensure_fail2ban || return 1

    # Vérifier que la jail existe avant d'agir
    if [ "$DRY_RUN" -ne 1 ] && ! fail2ban-client status "$jail" &>/dev/null; then
        log "ERROR" "Jail inexistante: $jail (voir '$PROG fail2ban jails')"
        return 1
    fi

    log "INFO" "Bannissement de $ip dans la jail $jail"
    if [ "$DRY_RUN" -eq 1 ]; then
        log "INFO" "[dry-run] fail2ban-client set $jail banip $ip"
        return 0
    fi
    fail2ban-client set "$jail" banip "$ip"
    return $?
}

# Débannir une IP (dans une jail, ou toutes les jails si non précisée)
fail2ban_unban() {
    local ip="$1"
    local jail="$2"

    if [ -z "$ip" ]; then
        log "ERROR" "IP requise pour le débannissement"
        return 1
    fi
    ensure_fail2ban || return 1

    local jails
    if [ -n "$jail" ]; then
        jails="$jail"
    else
        jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed -E 's/^[^:]+:[ \t]*//' | tr ',' ' ')
    fi

    log "INFO" "Débannissement de $ip"
    if [ "$DRY_RUN" -eq 1 ]; then
        log "INFO" "[dry-run] fail2ban-client unban $ip (jails: $jails)"
        return 0
    fi

    local done=1
    for j in $jails; do
        if fail2ban-client set "$j" unbanip "$ip" 2>/dev/null; then
            log "INFO" "$ip débannie de $j"
            done=0
        fi
    done
    return $done
}

# Activer une protection SSH par défaut (preset sécurisé)
fail2ban_setup_ssh() {
    ensure_fail2ban || return 1
    local maxretry="${1:-5}"
    local bantime="${2:-3600}"
    local findtime="${3:-600}"

    log "INFO" "Configuration de la jail sshd (maxretry=$maxretry, bantime=${bantime}s)"
    if [ "$DRY_RUN" -eq 1 ]; then
        log "INFO" "[dry-run] Écriture de /etc/fail2ban/jail.d/sshd.local"
        return 0
    fi

    mkdir -p /etc/fail2ban/jail.d
    cat > /etc/fail2ban/jail.d/sshd.local << EOF
[sshd]
enabled  = true
port     = ssh
maxretry = $maxretry
findtime = $findtime
bantime  = $bantime
EOF

    systemctl restart fail2ban
    if systemctl is-active --quiet fail2ban; then
        log "INFO" "Jail sshd activée"
        return 0
    else
        log "ERROR" "fail2ban n'a pas redémarré correctement"
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
    echo "8. Fail2ban (anti-brute force)"
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

interactive_menu() {
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
                        8)
                            # Sous-menu Fail2ban
                            while true; do
                                clear
                                echo "===== FAIL2BAN ====="
                                echo "1. Statut global"
                                echo "2. Lister les jails"
                                echo "3. Lister les IP bannies"
                                echo "4. Bannir une IP"
                                echo "5. Débannir une IP"
                                echo "6. Activer la protection SSH (preset)"
                                echo "0. Retour"
                                echo "===================="
                                echo -n "Choisissez une option: "
                                read -r f2b_choice
                                case $f2b_choice in
                                    1)
                                        fail2ban_status
                                        read -p "Appuyez sur Entrée pour continuer..."
                                        ;;
                                    2)
                                        fail2ban_list_jails
                                        read -p "Appuyez sur Entrée pour continuer..."
                                        ;;
                                    3)
                                        read -p "Jail (vide = toutes): " jail
                                        fail2ban_banned "$jail"
                                        read -p "Appuyez sur Entrée pour continuer..."
                                        ;;
                                    4)
                                        read -p "IP à bannir: " ip
                                        read -p "Jail [sshd]: " jail
                                        jail=${jail:-sshd}
                                        fail2ban_ban "$ip" "$jail"
                                        read -p "Appuyez sur Entrée pour continuer..."
                                        ;;
                                    5)
                                        read -p "IP à débannir: " ip
                                        read -p "Jail (vide = toutes): " jail
                                        fail2ban_unban "$ip" "$jail"
                                        read -p "Appuyez sur Entrée pour continuer..."
                                        ;;
                                    6)
                                        fail2ban_setup_ssh
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
                                certbot --nginx -d "$server_name" --non-interactive --agree-tos --email "$ADMIN_EMAIL"
                            else
                                echo "Certbot non installé. Installation..."
                                apt-get update
                                apt-get install -y certbot python3-certbot-nginx
                                certbot --nginx -d "$server_name" --non-interactive --agree-tos --email "$ADMIN_EMAIL"
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
                            
                            # Créer le script de sauvegarde (appelle la CLI de Rootopia)
                            local db_flag=""
                            [ "$include_databases" = "no" ] && db_flag="--no-db"
                            cat > "$CONFIG_DIR/auto_backup.sh" << EOF
#!/bin/bash
# Généré par Rootopia — sauvegarde automatique
SCRIPT="$SCRIPT_PATH"
if [ "$encrypt" = "yes" ]; then
    "\$SCRIPT" -y snapshot create --name "$snapshot_name" $db_flag --encrypt --password-stdin < "$CONFIG_DIR/backup_password"
else
    "\$SCRIPT" -y snapshot create --name "$snapshot_name" $db_flag
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

# ===== INTERFACE EN LIGNE DE COMMANDE (CLI) =====

# Sortie en erreur avec message
die() {
    log "ERROR" "$1"
    exit "${2:-1}"
}

print_usage() {
    cat << EOF
Rootopia v$VERSION — Gestion Linux centralisée

USAGE:
    $PROG [OPTIONS] <module> <action> [arguments]
    $PROG                       Lance le menu interactif
    $PROG menu                  Lance le menu interactif

OPTIONS GLOBALES:
    -h, --help        Afficher cette aide
    -V, --version     Afficher la version
    -y, --yes         Confirmer automatiquement (indispensable en non-interactif)
    -q, --quiet       Masquer les messages INFO
        --dry-run     Simuler les actions sensibles sans les exécuter

MODULES:
    dashboard                          Résumé du système
    service   <action> [service]       Services (systemd)
    user      <action> [options]       Utilisateurs
    group     <action> [args]          Groupes
    firewall  <action> [args]          Pare-feu iptables
    vpn       <action> [options]       VPN WireGuard
    fail2ban  <action> [args]          Anti brute-force fail2ban
    web       <action> [options]       Hébergement web nginx
    snapshot  <action> [options]       Snapshots & sauvegardes
    logs      <action> [args]          Logs & diagnostics

Aide d'un module :  $PROG <module> --help

EXEMPLES:
    $PROG dashboard
    $PROG service restart nginx
    $PROG user create --name alice --password 's3cret' --groups sudo
    $PROG firewall setup -y
    $PROG fail2ban ban 203.0.113.7 sshd
    $PROG snapshot create --name nightly --encrypt --password 'pass' -y
EOF
}

# ---- service ----
cmd_service() {
    local action="$1"; shift 2>/dev/null
    case "$action" in
        ""|-h|--help|help)
            echo "Usage: $PROG service <list|start|stop|restart|status|enable|disable|logs|config> [service]"
            return 0 ;;
        list) list_services ;;
        start|stop|restart|status|enable|disable|logs)
            [ -n "$1" ] || die "Nom du service requis: $PROG service $action <service>"
            manage_service "$1" "$action" ;;
        config)
            [ -n "$1" ] || die "Nom du service requis: $PROG service config <service>"
            edit_service_config "$1" ;;
        *) die "Action service inconnue: $action" ;;
    esac
}

# ---- user ----
cmd_user() {
    local action="$1"; shift 2>/dev/null
    local name="" password="" home="" shell="" groups="" keep_home="no" password_stdin=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --name) name="$2"; shift 2 ;;
            --password) password="$2"; shift 2 ;;
            --password-stdin) password_stdin=1; shift ;;
            --home) home="$2"; shift 2 ;;
            --shell) shell="$2"; shift 2 ;;
            --groups) groups="$2"; shift 2 ;;
            --keep-home) keep_home="yes"; shift ;;
            *) die "Option user inconnue: $1" ;;
        esac
    done
    case "$action" in
        ""|-h|--help|help)
            cat << EOF
Usage:
    $PROG user list
    $PROG user create --name N [--password P | --password-stdin] [--home DIR] [--shell SH] [--groups g1,g2]
    $PROG user delete --name N [--keep-home]
    $PROG user passwd --name N [--password P | --password-stdin]

Mots de passe : préférez --password-stdin (echo 'secret' | $PROG ...) ou le
prompt interactif. --password est accepté mais visible dans 'ps'.
EOF
            return 0 ;;
        list) list_users ;;
        create)
            [ -n "$name" ] || die "--name requis"
            password=$(resolve_secret "$password" "$password_stdin" "Mot de passe pour $name: ") \
                || die "Mot de passe requis (--password, --password-stdin ou terminal interactif)"
            create_user "$name" "$password" "$home" "$shell" "$groups" ;;
        delete)
            [ -n "$name" ] || die "--name requis"
            confirm "Supprimer l'utilisateur $name ?" || die "Annulé"
            delete_user "$name" "$keep_home" ;;
        passwd)
            [ -n "$name" ] || die "--name requis"
            password=$(resolve_secret "$password" "$password_stdin" "Nouveau mot de passe pour $name: ") \
                || die "Mot de passe requis (--password, --password-stdin ou terminal interactif)"
            change_user_password "$name" "$password" ;;
        *) die "Action user inconnue: $action" ;;
    esac
}

# ---- group ----
cmd_group() {
    local action="$1"; shift 2>/dev/null
    case "$action" in
        ""|-h|--help|help)
            cat << EOF
Usage:
    $PROG group create <nom>
    $PROG group delete <nom>
    $PROG group add <groupe> <user1,user2,...>
    $PROG group remove <groupe> <user1,user2,...>
EOF
            return 0 ;;
        create) [ -n "$1" ] || die "Nom du groupe requis"; manage_group "create" "$1" ;;
        delete)
            [ -n "$1" ] || die "Nom du groupe requis"
            confirm "Supprimer le groupe $1 ?" || die "Annulé"
            manage_group "delete" "$1" ;;
        add)    [ -n "$2" ] || die "Usage: $PROG group add <groupe> <users>"; manage_group "add_members" "$1" "$2" ;;
        remove) [ -n "$2" ] || die "Usage: $PROG group remove <groupe> <users>"; manage_group "remove_members" "$1" "$2" ;;
        *) die "Action group inconnue: $action" ;;
    esac
}

# ---- firewall ----
cmd_firewall() {
    local action="$1"; shift 2>/dev/null
    case "$action" in
        ""|-h|--help|help)
            cat << EOF
Usage:
    $PROG firewall list
    $PROG firewall setup            (réinitialise tout — preset sécurisé)
    $PROG firewall save
    $PROG firewall restore
    $PROG firewall add <table> <chaine> <regle...>
    $PROG firewall delete <table> <chaine> <numero>
EOF
            return 0 ;;
        list)    list_iptables_rules ;;
        save)    backup_iptables ;;
        restore) restore_iptables ;;
        setup)
            confirm "Réinitialiser TOUTES les règles iptables et appliquer le preset ?" || die "Annulé"
            setup_basic_firewall ;;
        add)
            local table="$1" chain="$2"; shift 2 2>/dev/null
            [ -n "$table" ] && [ -n "$chain" ] && [ -n "$1" ] || die "Usage: $PROG firewall add <table> <chaine> <regle...>"
            add_iptables_rule "$table" "$chain" "$*" ;;
        delete)
            [ -n "$3" ] || die "Usage: $PROG firewall delete <table> <chaine> <numero>"
            delete_iptables_rule "$1" "$2" "$3" ;;
        *) die "Action firewall inconnue: $action" ;;
    esac
}

# ---- vpn ----
cmd_vpn() {
    local action="$1"; shift 2>/dev/null
    local name="" server_pubkey="" endpoint="" allowed_ips="0.0.0.0/0" address=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --name) name="$2"; shift 2 ;;
            --server-pubkey) server_pubkey="$2"; shift 2 ;;
            --endpoint) endpoint="$2"; shift 2 ;;
            --allowed-ips) allowed_ips="$2"; shift 2 ;;
            --address) address="$2"; shift 2 ;;
            *) die "Option vpn inconnue: $1" ;;
        esac
    done
    case "$action" in
        ""|-h|--help|help)
            cat << EOF
Usage:
    $PROG vpn status
    $PROG vpn up | down
    $PROG vpn client-add --name N --server-pubkey K --endpoint E [--allowed-ips IPS] [--address 10.0.0.X]
    $PROG vpn client-list
    $PROG vpn client-revoke --name N

Sans --address, une IP libre dans 10.0.0.0/24 est attribuée automatiquement.
EOF
            return 0 ;;
        status) check_vpn_status ;;
        up)     systemctl start wg-quick@wg0 && log "INFO" "VPN démarré" ;;
        down)   systemctl stop wg-quick@wg0 && log "INFO" "VPN arrêté" ;;
        client-add)
            [ -n "$name" ] && [ -n "$server_pubkey" ] && [ -n "$endpoint" ] || die "--name, --server-pubkey et --endpoint requis"
            generate_wireguard_client "$name" "$server_pubkey" "$endpoint" "$allowed_ips" "$address" ;;
        client-list)
            echo "Clients VPN configurés:"
            ls -la /etc/wireguard/clients/ 2>/dev/null || echo "Aucun client trouvé" ;;
        client-revoke)
            [ -n "$name" ] || die "--name requis"
            if [ -f "/etc/wireguard/clients/${name}.pub" ]; then
                local pub; pub=$(cat "/etc/wireguard/clients/${name}.pub")
                wg set wg0 peer "$pub" remove && wg-quick save wg0
                rm -f "/etc/wireguard/clients/${name}".*
                log "INFO" "Client $name révoqué"
            else
                die "Client non trouvé: $name"
            fi ;;
        *) die "Action vpn inconnue: $action" ;;
    esac
}

# ---- fail2ban ----
cmd_fail2ban() {
    local action="$1"; shift 2>/dev/null
    case "$action" in
        ""|-h|--help|help)
            cat << EOF
Usage:
    $PROG fail2ban status
    $PROG fail2ban jails
    $PROG fail2ban banned [jail]
    $PROG fail2ban ban <ip> [jail=sshd]
    $PROG fail2ban unban <ip> [jail]
    $PROG fail2ban setup-ssh [maxretry=5] [bantime=3600] [findtime=600]
EOF
            return 0 ;;
        status)    fail2ban_status ;;
        jails)     fail2ban_list_jails ;;
        banned)    fail2ban_banned "$1" ;;
        ban)       [ -n "$1" ] || die "IP requise"; fail2ban_ban "$1" "$2" ;;
        unban)     [ -n "$1" ] || die "IP requise"; fail2ban_unban "$1" "$2" ;;
        setup-ssh) fail2ban_setup_ssh "$1" "$2" "$3" ;;
        *) die "Action fail2ban inconnue: $action" ;;
    esac
}

# ---- web ----
cmd_web() {
    local action="$1"; shift 2>/dev/null
    local name="" root="" server_name="" ssl="no" purge="no"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --name) name="$2"; shift 2 ;;
            --root) root="$2"; shift 2 ;;
            --server-name) server_name="$2"; shift 2 ;;
            --ssl) ssl="yes"; shift ;;
            --purge) purge="yes"; shift ;;
            *) die "Option web inconnue: $1" ;;
        esac
    done
    case "$action" in
        ""|-h|--help|help)
            cat << EOF
Usage:
    $PROG web list
    $PROG web create --name N [--root DIR] [--server-name DOMAINE] [--ssl]
    $PROG web delete --name N [--purge]
    $PROG web enable  --name N
    $PROG web disable --name N
    $PROG web ssl     --name N --server-name DOMAINE
EOF
            return 0 ;;
        list)
            echo "Sites disponibles:"; ls -1 /etc/nginx/sites-available/ 2>/dev/null
            echo -e "\nSites activés:";  ls -1 /etc/nginx/sites-enabled/ 2>/dev/null ;;
        create)
            [ -n "$name" ] || die "--name requis"
            create_website "$name" "$root" "$server_name" "$ssl" ;;
        delete)
            [ -n "$name" ] || die "--name requis"
            confirm "Supprimer le site $name ${purge:+(et ses fichiers)} ?" || die "Annulé"
            delete_website "$name" "$purge" ;;
        enable)
            [ -n "$name" ] || die "--name requis"
            ln -sf "/etc/nginx/sites-available/$name" "/etc/nginx/sites-enabled/"
            nginx -t && systemctl reload nginx && log "INFO" "Site $name activé" ;;
        disable)
            [ -n "$name" ] || die "--name requis"
            rm -f "/etc/nginx/sites-enabled/$name"
            systemctl reload nginx && log "INFO" "Site $name désactivé" ;;
        ssl)
            [ -n "$server_name" ] || die "--server-name requis"
            if ! command -v certbot &>/dev/null; then
                log "INFO" "Installation de certbot..."
                apt-get update && apt-get install -y certbot python3-certbot-nginx
            fi
            certbot --nginx -d "$server_name" --non-interactive --agree-tos --email "$ADMIN_EMAIL" ;;
        *) die "Action web inconnue: $action" ;;
    esac
}

# ---- snapshot ----
cmd_snapshot() {
    local action="$1"; shift 2>/dev/null
    local name="" file="" db="yes" encrypt="no" password="" password_stdin=0
    local host="" user="" path="" key=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --name) name="$2"; shift 2 ;;
            --file) file="$2"; shift 2 ;;
            --no-db) db="no"; shift ;;
            --encrypt) encrypt="yes"; shift ;;
            --password) password="$2"; shift 2 ;;
            --password-stdin) password_stdin=1; shift ;;
            --host) host="$2"; shift 2 ;;
            --user) user="$2"; shift 2 ;;
            --path) path="$2"; shift 2 ;;
            --key) key="$2"; shift 2 ;;
            *) die "Option snapshot inconnue: $1" ;;
        esac
    done
    case "$action" in
        ""|-h|--help|help)
            cat << EOF
Usage:
    $PROG snapshot list
    $PROG snapshot create  --name N [--no-db] [--encrypt (--password P | --password-stdin)]
    $PROG snapshot restore --file F [--no-db] [--password P | --password-stdin]
    $PROG snapshot upload  --file F --host H --user U --path P [--key K]

Mots de passe : préférez --password-stdin ou le prompt interactif (--password
est visible dans 'ps').
EOF
            return 0 ;;
        list) echo "Snapshots disponibles:"; ls -la "$SNAPSHOT_DIR" 2>/dev/null ;;
        create)
            [ -n "$name" ] || die "--name requis"
            if [ "$encrypt" = "yes" ]; then
                password=$(resolve_secret "$password" "$password_stdin" "Mot de passe de chiffrement: ") \
                    || die "Mot de passe requis avec --encrypt"
            fi
            create_snapshot "$name" "$db" "$encrypt" "$password" ;;
        restore)
            [ -n "$file" ] || die "--file requis"
            if [[ "$file" == *.enc ]]; then
                password=$(resolve_secret "$password" "$password_stdin" "Mot de passe de déchiffrement: ") \
                    || die "Mot de passe requis pour un snapshot chiffré"
            fi
            confirm "Restaurer $file (écrase la configuration courante) ?" || die "Annulé"
            restore_snapshot "$file" "$db" "$password" ;;
        upload)
            [ -n "$file" ] && [ -n "$host" ] && [ -n "$user" ] && [ -n "$path" ] || die "--file, --host, --user et --path requis"
            upload_snapshot "$file" "$host" "$user" "$path" "$key" ;;
        *) die "Action snapshot inconnue: $action" ;;
    esac
}

# ---- logs ----
cmd_logs() {
    local action="$1"; shift 2>/dev/null
    local lines=50 filter="" file=""
    case "$action" in
        ""|-h|--help|help)
            cat << EOF
Usage:
    $PROG logs view <syslog|auth|nginx|ftp|FICHIER> [--lines N] [--filter STR]
    $PROG logs diagnostics
EOF
            return 0 ;;
        diagnostics) run_diagnostics; return 0 ;;
        view)
            local src="$1"; shift 2>/dev/null
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --lines) lines="$2"; shift 2 ;;
                    --filter) filter="$2"; shift 2 ;;
                    *) die "Option logs inconnue: $1" ;;
                esac
            done
            case "$src" in
                syslog) file="/var/log/syslog" ;;
                auth)   file="/var/log/auth.log" ;;
                nginx)  file="/var/log/nginx/error.log" ;;
                ftp)    file="/var/log/vsftpd.log" ;;
                "")     die "Source requise: syslog|auth|nginx|ftp|FICHIER" ;;
                *)      file="$src" ;;
            esac
            view_logs "$file" "$lines" "$filter" ;;
        *) die "Action logs inconnue: $action" ;;
    esac
}

# ===== POINT D'ENTRÉE =====

main() {
    # Analyse des options globales (avant le nom du module)
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)    print_usage; exit 0 ;;
            -V|--version) echo "$PROG $VERSION"; exit 0 ;;
            -y|--yes)     ASSUME_YES=1; shift ;;
            -q|--quiet)   QUIET=1; shift ;;
            --dry-run)    DRY_RUN=1; shift ;;
            --)           shift; break ;;
            -*)           die "Option globale inconnue: $1 (voir '$PROG --help')" ;;
            *)            break ;;
        esac
    done

    local module="$1"; shift 2>/dev/null

    # Aide d'un module : accessible sans privilèges root
    if [ "$1" = "-h" ] || [ "$1" = "--help" ] || [ "$1" = "help" ]; then
        case "$module" in
            service)         cmd_service ;;
            user)            cmd_user ;;
            group)           cmd_group ;;
            firewall|fw)     cmd_firewall ;;
            vpn)             cmd_vpn ;;
            fail2ban|f2b)    cmd_fail2ban ;;
            web)             cmd_web ;;
            snapshot|backup) cmd_snapshot ;;
            logs)            cmd_logs ;;
            *)               print_usage ;;
        esac
        exit 0
    fi

    # Initialisation commune (droits + répertoires)
    check_root
    setup_directories

    # Aucun module : menu interactif classique
    if [ -z "$module" ] || [ "$module" = "menu" ]; then
        check_dependencies || die "Impossible de continuer sans les dépendances requises"
        interactive_menu
        return
    fi

    case "$module" in
        dashboard|status) get_system_summary ;;
        service)          cmd_service "$@" ;;
        user)             cmd_user "$@" ;;
        group)            cmd_group "$@" ;;
        firewall|fw)      cmd_firewall "$@" ;;
        vpn)              cmd_vpn "$@" ;;
        fail2ban|f2b)     cmd_fail2ban "$@" ;;
        web)              cmd_web "$@" ;;
        snapshot|backup)  cmd_snapshot "$@" ;;
        logs)             cmd_logs "$@" ;;
        help)             print_usage ;;
        *)                die "Module inconnu: $module (voir '$PROG --help')" ;;
    esac
}

# Exécuter la fonction principale si le script est exécuté directement
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi

