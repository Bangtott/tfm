#!/usr/bin/env bash
set -Eeuo pipefail

VERSION="1.2.0"
CONFIG_FILE="/etc/traffic-firewall-manager.conf"
UPDATE_SCRIPT="/usr/local/sbin/tfm-update-blocklists"
APPLY_SCRIPT="/usr/local/sbin/tfm-apply"

TG_URLS=(
  "https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list"
  "https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list"
)

LEASEWEB_ASNS=(
  AS16265 AS60781 AS28753 AS30633 AS38731 AS49367 AS51395
  AS50673 AS59253 AS133752 AS134351 AS6939
)

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf '\n==> %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }

CURRENT_SSH_IP=""
CURRENT_SSH_PORT=""
if [[ -n ${SSH_CONNECTION:-} ]]; then
  read -r CURRENT_SSH_IP _ _ CURRENT_SSH_PORT <<< "$SSH_CONNECTION"
fi

require_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Запустите скрипт от root: sudo bash $0"
}

is_ipv4() {
  local ip=$1 IFS=. octets i
  read -r -a octets <<< "$ip"
  [[ ${#octets[@]} -eq 4 ]] || return 1
  for i in "${octets[@]}"; do
    [[ $i =~ ^[0-9]{1,3}$ ]] || return 1
    ((10#$i <= 255)) || return 1
  done
}

is_port() { [[ $1 =~ ^[0-9]+$ ]] && ((10#$1 >= 1 && 10#$1 <= 65535)); }

ask_yes_no() {
  local prompt=$1 default=${2:-y} answer suffix
  [[ $default == y ]] && suffix='[Y/n]' || suffix='[y/N]'
  read -r -p "$prompt $suffix " answer
  answer=${answer:-$default}
  [[ $answer =~ ^[YyДд]$ ]]
}

is_domain() {
  local domain=$1 label IFS=.
  [[ ${#domain} -le 253 && $domain != .* && $domain != *. && $domain != *..* ]] || return 1
  [[ $domain =~ ^[A-Za-z0-9.-]+$ ]] || return 1
  read -r -a labels <<< "$domain"
  for label in "${labels[@]}"; do
    [[ -n $label && ${#label} -le 63 && $label != -* && $label != *- ]] || return 1
  done
}

resolve_ipv4_target() {
  local target=$1
  if is_ipv4 "$target"; then
    printf '%s\n' "$target"
  else
    getent ahostsv4 "$target" 2>/dev/null | awk '{print $1}' | sort -u
  fi
}

read_2222_targets() {
  local raw item resolved
  while true; do
    read -r -p 'IPv4 и/или домены для доступа к 2222/tcp (через пробел): ' raw
    raw=${raw//,/ }
    PARSED_2222_TARGETS=()
    for item in $raw; do
      if ! is_ipv4 "$item" && ! is_domain "$item"; then
        warn "Некорректный IPv4 или домен: $item"
        PARSED_2222_TARGETS=()
        break
      fi
      resolved=$(resolve_ipv4_target "$item")
      if [[ -z $resolved ]]; then
        warn "Не удалось получить IPv4 для $item"
        PARSED_2222_TARGETS=()
        break
      fi
      [[ " ${PARSED_2222_TARGETS[*]-} " == *" $item "* ]] || PARSED_2222_TARGETS+=("$item")
    done
    ((${#PARSED_2222_TARGETS[@]})) && return
    warn "Укажите хотя бы один рабочий IPv4 или домен для 2222/tcp"
  done
}
parse_ports() {
  local raw=$1 item
  PARSED_PORTS=()
  raw=${raw//,/ }
  for item in $raw; do
    is_port "$item" || die "Некорректный TCP-порт: $item"
    case $((10#$item)) in
      22|80|443|2222|8443) die "Порт $item настраивается отдельным шагом" ;;
    esac
    [[ " ${PARSED_PORTS[*]-} " == *" $((10#$item)) "* ]] || PARSED_PORTS+=("$((10#$item))")
  done
}

write_config() {
  local targets=$1 enable_8443=$2 enable_http_80=$3 enable_tg=$4 enable_asn=$5 enable_grchc=$6
  shift 6
  local extra_ports=$1
  install -d -m 0755 "$(dirname "$CONFIG_FILE")"
  {
    printf '# Managed by traffic-firewall-manager %s\n' "$VERSION"
    printf 'TRUSTED_2222_TARGETS=(%s)\n' "$targets"
    printf 'ENABLE_8443=%q\n' "$enable_8443"
    printf 'ENABLE_HTTP_80=%q\n' "$enable_http_80"
    printf 'ENABLE_TRAFFIC_GUARD=%q\n' "$enable_tg"
    printf 'ENABLE_ASN_BLOCK=%q\n' "$enable_asn"
    printf 'ENABLE_GRCHC_BLOCK=%q\n' "$enable_grchc"
    printf 'EXTRA_TCP_PORTS=(%s)\n' "$extra_ports"

  } > "$CONFIG_FILE"
  chmod 0600 "$CONFIG_FILE"
}

install_dependencies() {
  info "Установка зависимостей"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y ca-certificates curl iptables ipset iptables-persistent netfilter-persistent whois
}

install_safety_rules() {
  local target ip
  info "Установка временной защиты от потери SSH"
  iptables -w -N TFM-SAFETY 2>/dev/null || true
  iptables -w -F TFM-SAFETY
  for target in "$@"; do
    while IFS= read -r ip; do
      [[ -n $ip ]] && iptables -w -A TFM-SAFETY -s "$ip" -j ACCEPT
    done < <(resolve_ipv4_target "$target")
  done
  if [[ -n $CURRENT_SSH_IP ]] && is_ipv4 "$CURRENT_SSH_IP"; then
    iptables -w -A TFM-SAFETY -s "$CURRENT_SSH_IP" -j ACCEPT
  fi
  while iptables -w -C INPUT -j TFM-SAFETY 2>/dev/null; do iptables -w -D INPUT -j TFM-SAFETY; done
  iptables -w -I INPUT 1 -j TFM-SAFETY
  netfilter-persistent save >/dev/null
}

remove_safety_rules() {
  while iptables -w -C INPUT -j TFM-SAFETY 2>/dev/null; do iptables -w -D INPUT -j TFM-SAFETY; done
  iptables -w -F TFM-SAFETY 2>/dev/null || true
  iptables -w -X TFM-SAFETY 2>/dev/null || true
  netfilter-persistent save >/dev/null
}

emergency_handler() {
  local line=$1 code=$2
  warn "Ошибка на строке $line (код $code). TFM-SAFETY оставлен для сохранения SSH."
  netfilter-persistent save >/dev/null 2>&1 || true
  exit "$code"
}

cleanup_legacy_aio_rules() {
  info "Миграция старых правил aio_gentle"
  local chain set direction old_cron
  for chain in INPUT OUTPUT FORWARD; do
    case $chain in
      INPUT) direction=src ;;
      OUTPUT) direction=dst ;;
      FORWARD) direction=src,dst ;;
    esac
    for set in leaseweb_v4 lorrr_v4; do
      while iptables -w -C "$chain" -m set --match-set "$set" "$direction" -j DROP 2>/dev/null; do
        iptables -w -D "$chain" -m set --match-set "$set" "$direction" -j DROP
      done
    done
  done
  if command -v crontab >/dev/null 2>&1; then
    old_cron=$(mktemp)
    crontab -l 2>/dev/null | grep -vE '(block_leaseweb\.sh|update_lorrr\.sh)' > "$old_cron" || true
    crontab "$old_cron"
    rm -f "$old_cron"
  fi
  if [[ -f /etc/systemd/system/ipset-persistent.service ]] &&
     grep -q '^Description=Restore ipset sets before iptables$' /etc/systemd/system/ipset-persistent.service; then
    systemctl disable --now ipset-persistent.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/ipset-persistent.service
    systemctl daemon-reload
  fi
  ipset destroy leaseweb_v4 2>/dev/null || true
  ipset destroy lorrr_v4 2>/dev/null || true
}
remove_ufw_if_needed() {
  command -v ufw >/dev/null 2>&1 || return 0
  warn "Traffic Guard включает UFW даже тогда, когда UFW был неактивен."
  if ask_yes_no "Удалить UFW и использовать единый iptables-менеджер?" y; then
    ufw --force disable >/dev/null 2>&1 || true
    apt-get remove --purge -y ufw
  else
    die "Остановлено: с установленным UFW Traffic Guard снова возьмёт управление правилами."
  fi
}

install_traffic_guard() {
  info "Установка Traffic Guard"
  local installer
  installer=$(mktemp)
  trap 'rm -f "${installer:-}"' RETURN
  curl -fsSL --proto '=https' --tlsv1.2 \
    https://raw.githubusercontent.com/dotX12/traffic-guard/master/install.sh -o "$installer"
  bash "$installer"
  traffic-guard full \
    -u "${TG_URLS[0]}" \
    -u "${TG_URLS[1]}" \
    --enable-logging
  rm -f "$installer"
  trap - RETURN
}

install_helpers() {
  info "Установка идемпотентных обновляющих скриптов"
  install -d -m 0755 /usr/local/sbin

  install -m 0755 /dev/stdin "$UPDATE_SCRIPT" <<'EOF_UPDATE'
#!/usr/bin/env bash
set -Eeuo pipefail
source /etc/traffic-firewall-manager.conf

log() { printf '[tfm-update] %s\n' "$*"; }

atomic_set_from_stream() {
  local live=$1 tmp="${1}_new" maxelem=$2 input=$3
  ipset create "$live" hash:net family inet hashsize 4096 maxelem "$maxelem" -exist
  ipset create "$tmp" hash:net family inet hashsize 4096 maxelem "$maxelem" -exist
  ipset flush "$tmp"
  while IFS= read -r network; do
    [[ -n $network ]] && ipset add "$tmp" "$network" -exist
  done < "$input"
  ipset swap "$live" "$tmp"
  ipset destroy "$tmp"
}

tmpdir=$(mktemp -d)
trap 'rm -rf -- "$tmpdir"' EXIT

if [[ ${ENABLE_ASN_BLOCK:-0} == 1 ]]; then
  : > "$tmpdir/asn.txt"
  asns=(AS16265 AS60781 AS28753 AS30633 AS38731 AS49367 AS51395 AS50673 AS59253 AS133752 AS134351 AS6939)
  for asn in "${asns[@]}"; do
    whois -h whois.radb.net -- "-i origin $asn" 2>/dev/null |
      awk '/^route:/ {print $2}' >> "$tmpdir/asn.txt" || true
  done
  sort -u -o "$tmpdir/asn.txt" "$tmpdir/asn.txt"
  [[ -s $tmpdir/asn.txt ]] || { log "ASN-список пуст; старый набор сохранён"; exit 1; }
  atomic_set_from_stream TFM-LEASEWEB-V4 131072 "$tmpdir/asn.txt"
  log "Leaseweb/HE: $(wc -l < "$tmpdir/asn.txt") сетей"
fi

if [[ ${ENABLE_GRCHC_BLOCK:-0} == 1 ]]; then
  curl -4fsSL --proto '=https' --tlsv1.2 \
    https://raw.githubusercontent.com/Loorrr293/blocklist/main/blocklist.txt |
    awk '!/^#/ && $1 !~ /:/ && $1 != "" {print $1}' | sort -u > "$tmpdir/grchc.txt"
  [[ -s $tmpdir/grchc.txt ]] || { log "ГРЧЦ-список пуст; старый набор сохранён"; exit 1; }
  atomic_set_from_stream TFM-GRCHC-V4 524288 "$tmpdir/grchc.txt"
  log "ГРЧЦ: $(wc -l < "$tmpdir/grchc.txt") сетей"
fi

ipset save -f /etc/ipset.conf
/usr/local/sbin/tfm-apply --no-save
netfilter-persistent save >/dev/null
EOF_UPDATE

  install -m 0755 /dev/stdin "$APPLY_SCRIPT" <<'EOF_APPLY'
#!/usr/bin/env bash
set -Eeuo pipefail
source /etc/traffic-firewall-manager.conf

mapfile -t RESOLVED_2222_IPS < <(
  for target in "${TRUSTED_2222_TARGETS[@]}"; do
    getent ahostsv4 "$target" 2>/dev/null | awk '{print $1}'
  done | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/' | sort -u
)
if ((${#RESOLVED_2222_IPS[@]} == 0)); then
  echo "ERROR: ни один IPv4/домен для 2222/tcp не удалось разрешить" >&2
  exit 1
fi

ipt_delete_all() {
  local chain=$1 target=$2
  while iptables -w -C "$chain" -j "$target" 2>/dev/null; do
    iptables -w -D "$chain" -j "$target"
  done
}

ip6t_delete_all() {
  local chain=$1 target=$2
  while ip6tables -w -C "$chain" -j "$target" 2>/dev/null; do
    ip6tables -w -D "$chain" -j "$target"
  done
}

iptables -w -N TFM-ACCESS 2>/dev/null || true
iptables -w -F TFM-ACCESS
iptables -w -A TFM-ACCESS -i lo -j ACCEPT
iptables -w -A TFM-ACCESS -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -w -A TFM-ACCESS -p icmp -j ACCEPT
iptables -w -A TFM-ACCESS -p udp --sport 67 --dport 68 -j ACCEPT
iptables -w -A TFM-ACCESS -p tcp --dport 22 -j ACCEPT
iptables -w -A TFM-ACCESS -p tcp --dport 443 -j ACCEPT
if [[ ${ENABLE_HTTP_80:-0} == 1 ]]; then
  iptables -w -A TFM-ACCESS -p tcp --dport 80 -j ACCEPT
else
  iptables -w -A TFM-ACCESS -p tcp --dport 80 -j DROP
fi
if [[ ${ENABLE_8443:-0} == 1 ]]; then
  iptables -w -A TFM-ACCESS -p tcp --dport 8443 -j ACCEPT
else
  iptables -w -A TFM-ACCESS -p tcp --dport 8443 -j DROP
fi
for port in "${EXTRA_TCP_PORTS[@]}"; do
  iptables -w -A TFM-ACCESS -p tcp --dport "$port" -j ACCEPT
done
for ip in "${RESOLVED_2222_IPS[@]}"; do
  iptables -w -A TFM-ACCESS -p tcp -s "$ip" --dport 2222 -m conntrack --ctstate NEW -j ACCEPT
done
iptables -w -A TFM-ACCESS -p tcp --dport 2222 -j DROP
iptables -w -A TFM-ACCESS -j DROP

ip6tables -w -N TFM6-ACCESS 2>/dev/null || true
ip6tables -w -F TFM6-ACCESS
ip6tables -w -A TFM6-ACCESS -i lo -j ACCEPT
ip6tables -w -A TFM6-ACCESS -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip6tables -w -A TFM6-ACCESS -p ipv6-icmp -j ACCEPT
ip6tables -w -A TFM6-ACCESS -p udp --sport 547 --dport 546 -j ACCEPT
ip6tables -w -A TFM6-ACCESS -p tcp --dport 22 -j ACCEPT
ip6tables -w -A TFM6-ACCESS -p tcp --dport 443 -j ACCEPT
if [[ ${ENABLE_HTTP_80:-0} == 1 ]]; then
  ip6tables -w -A TFM6-ACCESS -p tcp --dport 80 -j ACCEPT
else
  ip6tables -w -A TFM6-ACCESS -p tcp --dport 80 -j DROP
fi
if [[ ${ENABLE_8443:-0} == 1 ]]; then
  ip6tables -w -A TFM6-ACCESS -p tcp --dport 8443 -j ACCEPT
else
  ip6tables -w -A TFM6-ACCESS -p tcp --dport 8443 -j DROP
fi
for port in "${EXTRA_TCP_PORTS[@]}"; do
  ip6tables -w -A TFM6-ACCESS -p tcp --dport "$port" -j ACCEPT
done
ip6tables -w -A TFM6-ACCESS -p tcp --dport 2222 -j DROP
ip6tables -w -A TFM6-ACCESS -j DROP

iptables -w -N TFM-BLOCK 2>/dev/null || true
iptables -w -F TFM-BLOCK
if [[ ${ENABLE_ASN_BLOCK:-0} == 1 ]]; then
  ipset create TFM-LEASEWEB-V4 hash:net family inet hashsize 4096 maxelem 131072 -exist
  iptables -w -A TFM-BLOCK -m set --match-set TFM-LEASEWEB-V4 src -j DROP
fi
if [[ ${ENABLE_GRCHC_BLOCK:-0} == 1 ]]; then
  ipset create TFM-GRCHC-V4 hash:net family inet hashsize 4096 maxelem 524288 -exist
  iptables -w -A TFM-BLOCK -m set --match-set TFM-GRCHC-V4 src -j DROP
fi
iptables -w -A TFM-BLOCK -j RETURN

# Порядок: Traffic Guard -> TFM blocklists -> whitelist -> DROP.
ipt_delete_all INPUT TFM-ACCESS
ipt_delete_all INPUT TFM-BLOCK
ipt_delete_all INPUT SCANNERS-BLOCK
iptables -w -I INPUT 1 -j TFM-ACCESS
iptables -w -I INPUT 1 -j TFM-BLOCK
[[ ${ENABLE_TRAFFIC_GUARD:-0} == 1 ]] && iptables -w -L SCANNERS-BLOCK -n >/dev/null 2>&1 && iptables -w -I INPUT 1 -j SCANNERS-BLOCK
if iptables -w -L TFM-SAFETY -n >/dev/null 2>&1 && iptables -w -C INPUT -j TFM-SAFETY 2>/dev/null; then
  ipt_delete_all INPUT TFM-SAFETY
  iptables -w -I INPUT 1 -j TFM-SAFETY
fi

ip6t_delete_all INPUT TFM6-ACCESS
ip6t_delete_all INPUT SCANNERS-BLOCK
ip6tables -w -I INPUT 1 -j TFM6-ACCESS
[[ ${ENABLE_TRAFFIC_GUARD:-0} == 1 ]] && ip6tables -w -L SCANNERS-BLOCK -n >/dev/null 2>&1 && ip6tables -w -I INPUT 1 -j SCANNERS-BLOCK

if [[ ${1:-} != --no-save ]]; then
  ipset save -f /etc/ipset.conf
  netfilter-persistent save >/dev/null
fi
EOF_APPLY
}

install_systemd_units() {
  info "Настройка восстановления и обновлений"
  install -m 0644 /dev/stdin /etc/systemd/system/tfm-ipset-restore.service <<'EOF'
[Unit]
Description=Restore Traffic Firewall Manager ipsets
DefaultDependencies=no
Before=netfilter-persistent.service network-pre.target
ConditionFileNotEmpty=/etc/ipset.conf

[Service]
Type=oneshot
ExecStart=/usr/sbin/ipset restore -exist -f /etc/ipset.conf
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
RequiredBy=netfilter-persistent.service
EOF

  install -m 0644 /dev/stdin /etc/systemd/system/tfm-update.service <<EOF
[Unit]
Description=Update Traffic Firewall Manager blocklists
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$UPDATE_SCRIPT
EOF

  install -m 0644 /dev/stdin /etc/systemd/system/tfm-update.timer <<'EOF'
[Unit]
Description=Weekly update of Traffic Firewall Manager blocklists

[Timer]
OnCalendar=Mon *-*-* 03:15:00
RandomizedDelaySec=20m
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable tfm-ipset-restore.service netfilter-persistent.service tfm-update.timer
  systemctl start tfm-update.timer
}

show_status() {
  printf '\n--- Конфигурация ---\n'
  sed -n '2,$p' "$CONFIG_FILE"
  printf '\n--- Управляемые INPUT-jump правила (должно быть по одному) ---\n'
  iptables -S INPUT | grep -E -- '-j (TFM-ACCESS|TFM-BLOCK|SCANNERS-BLOCK)' || true
  printf '\n--- TFM-ACCESS ---\n'
  iptables -S TFM-ACCESS || true
  printf '\n--- TFM-BLOCK ---\n'
  iptables -S TFM-BLOCK || true
  printf '\n--- ipset ---\n'
  ipset list -name | grep -E '^(TFM-|SCANNERS-BLOCK)' || true
}

reset_firewall() {
  local answer backup_dir table cmd unit
  printf '\nПОЛНЫЙ СБРОС FIREWALL\n'
  warn "Будут удалены ВСЕ правила IPv4/IPv6, включая Docker, Fail2Ban, Traffic Guard и чужие правила."
  warn "Политики INPUT/OUTPUT/FORWARD станут ACCEPT. Сервер останется полностью открытым."
  read -r -p 'Для подтверждения введите RESET: ' answer
  [[ $answer == RESET ]] || { warn "Сброс отменён"; return; }

  backup_dir="/var/backups/tfm/$(date +%Y%m%d-%H%M%S)"
  install -d -m 0700 "$backup_dir"
  iptables-save > "$backup_dir/iptables.v4" 2>/dev/null || true
  ip6tables-save > "$backup_dir/iptables.v6" 2>/dev/null || true
  ipset save > "$backup_dir/ipset.conf" 2>/dev/null || true

  for unit in tfm-update.timer tfm-update.service tfm-ipset-restore.service \
              antiscan-ipset-restore.service antiscan-move-rules.service \
              antiscan-aggregate.timer antiscan-aggregate.service; do
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
  done
  command -v ufw >/dev/null 2>&1 && ufw --force disable >/dev/null 2>&1 || true

  for cmd in iptables ip6tables; do
    "$cmd" -w -P INPUT ACCEPT
    "$cmd" -w -P OUTPUT ACCEPT
    "$cmd" -w -P FORWARD ACCEPT
    for table in filter nat mangle raw security; do
      "$cmd" -w -t "$table" -F 2>/dev/null || true
      "$cmd" -w -t "$table" -X 2>/dev/null || true
    done
  done
  ipset flush 2>/dev/null || true
  ipset destroy 2>/dev/null || true
  : > /etc/ipset.conf
  netfilter-persistent save >/dev/null 2>&1 || true
  systemctl daemon-reload

  info "Firewall сброшен. Все политики ACCEPT, пользовательских правил нет."
  printf 'Резервная копия: %s\n' "$backup_dir"
}

wizard() {
  local enable_8443=0 enable_http_80=0 enable_tg=0 enable_asn=0 enable_grchc=0 raw targets_q

  printf 'Traffic Firewall Manager %s\n' "$VERSION"
  printf 'Разрешаются только выбранные входящие порты; весь остальной входящий трафик блокируется.\n'
  printf '22/tcp и 443/tcp открыты для всех. Доверенные IPv4 используются только для 2222/tcp.\n\n'

  read_2222_targets
  printf -v targets_q '%q ' "${PARSED_2222_TARGETS[@]}"

  ask_yes_no "Открыть 8443/tcp для всех IPv4/IPv6? (Нет = закрыть полностью)" n && enable_8443=1
  ask_yes_no "Открыть 80/tcp для всех IPv4/IPv6? (Нет = закрыть полностью)" n && enable_http_80=1


  read -r -p "Дополнительные TCP-порты открыть для всех IPv4/IPv6 (через пробел, пусто = нет): " raw
  parse_ports "$raw"
  local extra_ports_q=""
  if ((${#PARSED_PORTS[@]})); then printf -v extra_ports_q '%q ' "${PARSED_PORTS[@]}"; fi

  ask_yes_no "Установить/обновить Traffic Guard? (блокировка на всех портах)" y && enable_tg=1
  ask_yes_no "Включить Leaseweb & HE? (блокировка на всех портах)" y && enable_asn=1
  ask_yes_no "Включить блокировку ГРЧЦ? (на всех портах)" y && enable_grchc=1

  printf '\nБудет применено:\n'
  printf '  22/tcp: открыт для всех\n  443/tcp: открыт для всех\n'
  printf '  2222/tcp: только указанные IPv4/домены: %s\n' "${PARSED_2222_TARGETS[*]}"
  [[ $enable_http_80 == 1 ]] && printf '  80/tcp: открыт для всех\n' || printf '  80/tcp: закрыт\n'
  [[ $enable_8443 == 1 ]] && printf '  8443/tcp: открыт для всех\n' || printf '  8443/tcp: закрыт\n'
  [[ -n $extra_ports_q ]] && printf '  Дополнительные TCP-порты: открыты для всех\n'
  printf '  Traffic Guard: %s; Leaseweb/HE: %s; ГРЧЦ: %s\n' "$enable_tg" "$enable_asn" "$enable_grchc"
  ask_yes_no "Продолжить?" y || exit 0

  # Конфиг с allow-правилами создаётся до любых операций с firewall.
  write_config "$targets_q" "$enable_8443" "$enable_http_80" "$enable_tg" "$enable_asn" "$enable_grchc" \
    "$extra_ports_q"

  install_dependencies
  install_safety_rules "${PARSED_2222_TARGETS[@]}"
  trap 'emergency_handler "$LINENO" "$?"' ERR
  if ask_yes_no "Удалить старые правила/cron модулей aio_gentle перед миграцией?" y; then
    cleanup_legacy_aio_rules
  fi
  if [[ $enable_tg == 1 ]]; then
    remove_ufw_if_needed
    install_traffic_guard
  fi
  install_helpers
  install_systemd_units

  # Сначала создаём allow/drop цепочку, затем загружаем внешние списки.
  "$APPLY_SCRIPT"
  if [[ $enable_asn == 1 || $enable_grchc == 1 ]]; then
    "$UPDATE_SCRIPT"
  fi
  "$APPLY_SCRIPT"
  remove_safety_rules
  trap - ERR
  install -m 0755 "$0" /usr/local/sbin/tfm.sh
  show_status
  info "Готово. В дальнейшем запускайте: sudo tfm.sh"
}

run_saved_safely() {
  local command=$1
  source "$CONFIG_FILE"
  install_safety_rules "${TRUSTED_2222_TARGETS[@]}"
  trap 'emergency_handler "$LINENO" "$?"' ERR
  "$command"
  remove_safety_rules
  trap - ERR
}

main_menu() {
  local choice
  while true; do
    printf '\nTraffic Firewall Manager\n'
    printf '  1) Установить или изменить настройки\n'
    printf '  2) Применить сохранённые правила\n'
    printf '  3) Обновить блок-листы\n'
    printf '  4) Показать состояние\n'
    printf '  5) Полностью сбросить firewall (всё открыть)\n'
    printf '  6) Выход\n'
    read -r -p 'Выберите действие [1-6]: ' choice
    case $choice in
      1) wizard; return ;;
      2) [[ -f $CONFIG_FILE ]] || { warn "Сначала выполните установку"; continue; }; run_saved_safely "$APPLY_SCRIPT"; show_status ;;
      3) [[ -f $CONFIG_FILE ]] || { warn "Сначала выполните установку"; continue; }; run_saved_safely "$UPDATE_SCRIPT"; show_status ;;
      4) [[ -f $CONFIG_FILE ]] || { warn "Сначала выполните установку"; continue; }; show_status ;;
      5) reset_firewall ;;
      6) return ;;
      *) warn "Введите число от 1 до 6" ;;
    esac
  done
}

main() {
  require_root
  [[ $# -eq 0 ]] || die "Аргументы не нужны: просто запустите $0"
  main_menu
}

main "$@"
