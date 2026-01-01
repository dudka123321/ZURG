#!/bin/bash
# BugBounty Scanner v1.8.6 - ZURG Edition - Clean Nmap Output + Aort Fail-safe Integration
# Refactored: Removed Nuclei, AI Reports, and Metasploit. Added Ports Scan module.

set -o errexit
set -o nounset

target=""
target_cms=""
TIMEOUT_SECONDS=140000
CONFIG_FILE="$HOME/.config/ZURG/config.yaml"

# ====================================================================
# PATHS CONFIGURATION
# ====================================================================
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HARVESTER_DIR="/home/wispis/theHarvester"

# ====================================================================
# RATE LIMIT CHECKER
# ====================================================================
RL_CHECKER_RAW="assets/scripts/rl_checker.py"
RL_CHECKER_SCRIPT="${SCRIPT_DIR}/${RL_CHECKER_RAW}"

# TOOLS list (Removed Nuclei & MSF)
TOOLS=("subfinder" "chaos" "findomain" "amass" "puredns" "assetfinder" "dnsx" "naabu" "nmap" "httpx" "gau" "waybackpy" "ffuf" "katana" "podman" "jq" "aort")

# Флаги выполнения
do_subdomains=false
do_paths=false
do_ports=false

# Состояния
rate_limit_block=false
rate_limit_checked=false

# VPS Config placeholders
VPS_ENABLED="false"
VPS_SSH_STR=""
VPS_NAABU_PATH=""
VPS_NMAP_PATH=""

# ====================================================================
# Функции Log и Banner
# ====================================================================

log(){ echo -e "[$(date +%H:%M:%S)] $*"; }

banner(){
    echo -e "\e[94m"
    cat << "EOF"
███████╗██╗   ██╗██████╗  ██████╗
╚══███╔╝██║   ██║██╔══██╗██╔════╝
  ███╔╝ ██║   ██║██████╔╝██║  ███╗
 ███╔╝  ██║   ██║██╔══██╗██║   ██║
███████╗╚██████╔╝██║  ██║╚████╔╝
╚══════╝ ╚═════╝ ╚═╝  ╚══╝ ╚═════╝

Was Created by WISPIS - ZURG
Version: 1.8.6 (Ports Focused)
EOF
    echo -e "\e[0m"
    echo "──────────────────────────────────────────────"
}

usage(){
    banner
    echo "Usage: $0 -t <target_domain> [OPTIONS]"
    echo ""
    echo "OPTIONS:"
    echo "  -h                  Show this help message."
    echo "  -t <target_domain>  Target domain for testing (REQUIRED)."
    echo "  -cms <cms_name>     Target specific CMS scanning (Supported: wp)."
    echo ""
    echo "MODULES:"
    echo "  [1] Subdomains Enumeration"
    echo "  [2] Paths Enumeration"
    echo "  [3] Ports Scan (Nmap)"
    echo "  [4] Todos (All Pipeline)"
    echo "──────────────────────────────────────────────"
    exit 0
}

# ====================================================================
# CONFIG LOADER
# ====================================================================

load_config(){
    log "[INFO] Checking dependencies and config file..."

    if ! command -v yq >/dev/null 2>&1; then
        log "[CRIT] yq is not installed. Please install it."
        exit 1
    fi

    if [ ! -f "$CONFIG_FILE" ]; then
        log "[CRIT] Configuration file not found: $CONFIG_FILE."
        exit 1
    fi

    OUT_BASE="$(yq -r '.core.output_base' "$CONFIG_FILE")"
    RAW_FFUF_WORDLIST="$(yq -r '.wordlists.ffuf' "$CONFIG_FILE")"
    GOOFUZZ_KEYS_PATH="$(yq -r '.wordlists.goofuzz_keys // ""' "$CONFIG_FILE")"
    RAW_PUREDNS_WORDLIST="$(yq -r '.wordlists.puredns' "$CONFIG_FILE")"
    PROJECTDISCOVERY_API_KEY="$(yq -r '.api_keys.projectdiscovery' "$CONFIG_FILE")"
    WPSCAN_API_KEY="$(yq -r '.api_keys.wpscan' "$CONFIG_FILE")"

    VPS_ENABLED="$(yq -r '.vps.enabled // "false"' "$CONFIG_FILE")"
    VPS_SSH_STR="$(yq -r '.vps.ssh_connection // ""' "$CONFIG_FILE")"
    VPS_NAABU_PATH="$(yq -r '.vps.remote_naabu_path // "naabu"' "$CONFIG_FILE")"
    VPS_NMAP_PATH="$(yq -r '.vps.remote_nmap_path // "nmap"' "$CONFIG_FILE")"

    if [[ "$RAW_FFUF_WORDLIST" != /* ]]; then FFUF_WORDLIST="${SCRIPT_DIR}/${RAW_FFUF_WORDLIST}"; else FFUF_WORDLIST="$RAW_FFUF_WORDLIST"; fi
    if [[ "$RAW_PUREDNS_WORDLIST" != /* ]]; then PUREDNS_WORDLIST="${SCRIPT_DIR}/${RAW_PUREDNS_WORDLIST}"; else PUREDNS_WORDLIST="$RAW_PUREDNS_WORDLIST"; fi
    if [ -z "$GOOFUZZ_KEYS_PATH" ] || [ "$GOOFUZZ_KEYS_PATH" = "null" ]; then
    log "[WARN] GooFuzz keys path not found in config. GooFuzz might fail."
fi
    FFUF_WORDLIST=$(echo "$FFUF_WORDLIST" | sed 's/\/\.\//\//g')
    PUREDNS_WORDLIST=$(echo "$PUREDNS_WORDLIST" | sed 's/\/\.\//\//g')

    if [ "$OUT_BASE" = "null" ] || [ -z "$OUT_BASE" ]; then
        log "[CRIT] Configuration error: core.output_base is missing."
        exit 1
    fi
}

# ====================================================================
# SETUP & ARGS
# ====================================================================

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h) usage ;;
        -t) target="$2"; shift 2 ;;
        -cms) target_cms="$2"; shift 2 ;;
        -*) log "[CRIT] Invalid option: $1"; usage ;;
        *) log "[CRIT] Invalid argument: $1"; usage ;;
    esac
done

banner
load_config

if [ -z "$target" ]; then
    log "[CRIT] Target not provided."
    exit 1
fi

domain="$(echo "$target" | sed -E 's#https?://##' | sed 's#/.*##')"
OUT_BASE="${OUT_BASE%/}"
outdir="${OUT_BASE}/${domain//\//_}"

# Reduced directory structure
mkdir -p "$outdir"/{SUBDOMAINS,PATHS,LOGS,INFRA_SCAN,VULN_SCAN}

echo "Objetivo: $domain"
if [ "$VPS_ENABLED" == "true" ]; then
    echo "Scan Mode: HYBRID (VPS Active: $VPS_SSH_STR)"
else
    echo "Scan Mode: LOCAL ONLY"
fi
echo "Salida: $outdir"
echo "──────────────────────────────────────────────"

# ====================================================================
# HELPER FUNCTIONS
# ====================================================================

_timeout_cmd(){
  if timeout --help 2>&1 | grep -q -- '--foreground'; then
    timeout --foreground "$@"
  else
    timeout "$@"
  fi
}

move_file() {
    local file="$1"
    local dest="$2"
    if [ -f "$file" ]; then mv "$file" "$dest"; fi
}

organize_subdomains_files(){
    log "[INFO] Organizing Subdomains Enumeration files..."
    move_file "$outdir/theHarvester.txt" "$outdir/SUBDOMAINS/"
    move_file "$outdir/assetfinder.txt" "$outdir/SUBDOMAINS/"
    move_file "$outdir/subfinder.txt" "$outdir/SUBDOMAINS/"
    move_file "$outdir/findomain.txt" "$outdir/SUBDOMAINS/"
    move_file "$outdir/alterx.txt" "$outdir/SUBDOMAINS/"
    move_file "$outdir/chaos.txt" "$outdir/SUBDOMAINS/"
    move_file "$outdir/puredns.txt" "$outdir/SUBDOMAINS/"
    move_file "$outdir/aort.txt" "$outdir/SUBDOMAINS/"
}

organize_paths_files(){
    log "[INFO] Organizing Paths Enumeration files..."
    move_file "$outdir/gau.txt" "$outdir/PATHS/"
    move_file "$outdir/goofuzz.txt" "$outdir/PATHS/"
    move_file "$outdir/ffuf.txt" "$outdir/PATHS/"
    move_file "$outdir/katana.txt" "$outdir/PATHS/"
    move_file "$outdir/waybackpy.txt" "$outdir/PATHS/"
    find "$outdir" -maxdepth 1 -name "*.txt" -exec mv {} "$outdir/LOGS/" \; 2>/dev/null || true
}

echo "Seleccione los módulos a ejecutar:"
echo "[1] Subdomains Enumeration"
echo "[2] Paths Enumeration"
echo "[3] Ports Scan (Nmap)"
echo "[4] Todos (All Pipeline)"
read -rp "Opción: " mod_choice

case $mod_choice in
  1) do_subdomains=true ;;
  2) do_paths=true ;;
  3) do_ports=true ;;
  4) do_subdomains=true; do_paths=true; do_ports=true ;;
  *) echo "Opción inválida"; exit 1 ;;
esac

check_tools(){
  for t in "${TOOLS[@]}"; do
    if [ "$VPS_ENABLED" == "true" ]; then
        if [[ "$t" == "naabu" ]] || [[ "$t" == "nmap" ]]; then continue; fi
    fi
    if ! command -v "$t" >/dev/null 2>&1; then
      log "[WARN] $t не найден локально."
    fi
  done
}

run_tool(){
  local name="$1"
  local cmd="$2"
  local outfile="$3"
  log "[INFO] $name..."
  if _timeout_cmd "$TIMEOUT_SECONDS" bash -c "$cmd" >"$outfile" 2>/dev/null; then
    log "[OK] $name → $outfile"
  else
    log "[WARN] $name timeout/failed"
  fi
}

check_rate_limit(){
    if [ "$rate_limit_checked" = true ]; then return 0; fi
    log "[INFO] Running Rate Limit Check..."
    rate_limit_checked=true
    if [ ! -f "$RL_CHECKER_SCRIPT" ]; then return 0; fi
    local result=$(_timeout_cmd 60 python "$RL_CHECKER_SCRIPT" "$domain" 2>/dev/null | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')
    if [ "$result" = "BLOCK" ]; then
        log "[CRIT] Rate limit detected (BLOCK)."
        rate_limit_block=true
    elif [ "$result" = "OK" ]; then
        log "[OK] Rate limit check passed."
    fi
}

# ====================================================================
# MODULES
# ====================================================================

run_subdomains_enumeration(){
  log "[START] Start Subdomains Enumeration"

  # 1. THE HARVESTER MODULE
  log "[INFO] Запуск theHarvester (Log-Extraction Mode)..."
  local harvester_log="$outdir/LOGS/theHarvester_exec.log"
  local harvester_final="$outdir/theHarvester.txt"

  if _timeout_cmd "$TIMEOUT_SECONDS" uv run --active --project "$HARVESTER_DIR" theHarvester -b all -q -d "$domain" > "$harvester_log" 2>&1; then
      log "[INFO] Извлечение поддоменов из лога..."
      awk '/\[\*\] Hosts found:/,/^$/' "$harvester_log" | \
      grep -vE '\[\*\]|---|^\s*$' | \
      cut -d':' -f1 | \
      sed -E 's/^\*\.//; s/^\.//' | \
      grep -E '^([a-zA-Z0-9](([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z0-9]{2,})$' | \
      sort -u >> "$harvester_final"
  fi

  # 2. AORT MODULE (Fail-safe logic)
  log "[INFO] Запуск aort (Log-Extraction Mode - Fail-safe)..."
  local aort_log="$outdir/LOGS/aort_log.txt"
  local aort_final="$outdir/aort.txt"

  _timeout_cmd "$TIMEOUT_SECONDS" aort -d "$domain" --quiet --whois --enum --wayback > "$aort_log" 2>&1 || true

  if [ -f "$aort_log" ]; then
      log "[INFO] Извлечение поддоменов из лога aort..."
      grep -E '^\|' "$aort_log" | \
      sed 's/|//g' | \
      awk '{$1=$1};1' | \
      sed -E 's/^\*\.//; s/^\s*//' | \
      awk '{print $1}' | \
      sort -u >> "$aort_final"

      if [ -s "$aort_final" ]; then
          log "[OK] Aort parsed successfully: $(wc -l < "$aort_final") subdomains found."
      fi
  fi

  log "[INFO] Запуск GooFuzz (Subdomains Dorking Mode)..."
  local goofuzz_subs_log="$outdir/LOGS/goofuzz_subs_log.txt"
  local goofuzz_subs_final="$outdir/SUBDOMAINS/goofuzz.txt"

   if [ -f "$GOOFUZZ_KEYS_PATH" ]; then
      # Извлекаем директорию и имя файла ключей
      local keys_dir=$(dirname "$GOOFUZZ_KEYS_PATH")
      local keys_file=$(basename "$GOOFUZZ_KEYS_PATH")

      # Запуск через Docker. Используем -i без -t для стабильности в скриптах.
      # Монтируем директорию с ключами в /mnt контейнера.
      # Флаги: -p 10 (pages), -s (subdomains)
      _timeout_cmd "$TIMEOUT_SECONDS" docker run --rm \
          -v "${keys_dir}:/mnt:ro" \
          goofuzz -t "$domain" -k "/mnt/${keys_file}" \
          -p 10 -s > "$goofuzz_subs_log" 2>&1 || true

      if [ -f "$goofuzz_subs_log" ]; then
          # Проверяем, есть ли в логе фраза об отсутствии результатов
          if grep -q "Sorry, no subdomains found for" "$goofuzz_subs_log"; then
              log "[INFO] GooFuzz: No subdomains found via Dorks."
          else
              log "[INFO] Извлечение поддоменов из GooFuzz..."
              # Парсим строки, оканчивающиеся на целевой домен (например, sub.domain.com)
              grep -E "\.$domain$" "$goofuzz_subs_log" | sort -u >> "$goofuzz_subs_final"

              if [ -s "$goofuzz_subs_final" ]; then
                  log "[OK] GooFuzz found $(wc -l < "$goofuzz_subs_final") subdomains."
              fi
          fi
      fi
  else
      log "[WARN] GooFuzz skipped: Keys file not found at $GOOFUZZ_KEYS_PATH"
  fi

  # 3. Остальные инструменты
  run_tool "subfinder" "subfinder -d $domain -silent" "$outdir/subfinder.txt"
  run_tool "assetfinder" "assetfinder --subs-only $domain" "$outdir/assetfinder.txt"
  run_tool "findomain" "findomain -q -t $domain" "$outdir/findomain.txt"
  run_tool "alterx" "chaos -key $PROJECTDISCOVERY_API_KEY -silent -d $domain | alterx -silent -enrich | dnsx -silent" "$outdir/alterx.txt"
  run_tool "chaos" "chaos -key $PROJECTDISCOVERY_API_KEY -silent -d $domain" "$outdir/chaos.txt"
  run_tool "puredns" "puredns bruteforce $PUREDNS_WORDLIST $domain" "$outdir/puredns.txt"

  organize_subdomains_files

  # 4. Consolidation & Validation (httpx)
  log "[INFO] Consolidating and Validating Subdomains..."
  pushd "$outdir/SUBDOMAINS" > /dev/null
    cat * | sort -u >> ALL_SUBDOMAINS.txt
    cat ALL_SUBDOMAINS.txt | grep "$domain" | /root/go/bin/httpx -silent -sc -location -title >> ACTIVE_SUBDOMAINS.txt
  popd > /dev/null

  log "[END] End Subdomains Enumeration"
}

run_paths_enumeration(){
  log "[START] Start Paths Enumeration"

  check_rate_limit

  # --- ГРУППА 1: ПАССИВНЫЙ/АРХИВНЫЙ СБОР ---
  log "[INFO] Running Passive Path Discovery..."
  if [ -f "$GOOFUZZ_KEYS_PATH" ]; then
      local keys_dir=$(dirname "$GOOFUZZ_KEYS_PATH")
      local keys_file=$(basename "$GOOFUZZ_KEYS_PATH")
      _timeout_cmd "$TIMEOUT_SECONDS" docker run --rm \
          -v "${keys_dir}:/mnt:ro" \
          goofuzz -t "$domain" -k "/mnt/${keys_file}" \
          -e php,bak,old,sql,conf,env,log -p 10 > "$outdir/LOGS/goofuzz_log.txt" 2>&1 || true
      if [ -f "$outdir/LOGS/goofuzz_log.txt" ]; then
          grep -E '^https?://' "$outdir/LOGS/goofuzz_log.txt" | sort -u >> "$outdir/goofuzz.txt"
      fi
  fi

  run_tool "waybackpy" "waybackpy --url \"$domain\" --cdx --match-type \"host\" --cdx-print \"original\" --collapse \"urlkey\"" "$outdir/waybackpy.txt"
  run_tool "gau" "gau $domain" "$outdir/gau.txt"

  # --- ГРУППА 2: АКТИВНЫЙ СБОР ---
  if [ "$rate_limit_block" = false ]; then
      log "[INFO] Rate Limit OK. Running Active Discovery..."
      run_tool "katana" "katana -silent -u $domain -rl 15 -fs fqdn -jc -jsl" "$outdir/katana.txt"
      if [ -f "$FFUF_WORDLIST" ]; then
          run_tool "ffuf" "ffuf -u https://$domain/FUZZ -w $FFUF_WORDLIST -t 40 -fc 404 -ic -noninteractive" "$outdir/ffuf.txt"
      fi
  else
      log "[WARN] Rate Limit BLOCK detected. Skipping Katana and FFUF."
  fi

  organize_paths_files

  # --- ЛОГИКА ОЧИСТКИ FFUF ---
  if [ -f "$outdir/PATHS/ffuf.txt" ]; then
      log "[INFO] Filtering FFUF output..."
      local ffuf_raw="$outdir/PATHS/ffuf.txt"
      local ffuf_clean="$outdir/PATHS/ffuf_clean.txt"
      local ffuf_stripped="$outdir/LOGS/ffuf_stripped.tmp"
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" "$ffuf_raw" | grep "\[Status:" | tr -d '\r' > "$ffuf_stripped"
      local bad_sizes=$(grep -E "abhsdw01282|abhsdw01283|abhsdw01284" "$ffuf_stripped" | awk -F'Size: ' '{print $2}' | awk -F',' '{print $1}' | sort -u)
      if [ -n "$bad_sizes" ]; then
          local size_pattern=$(echo "$bad_sizes" | tr '\n' '|' | sed 's/|$//')
          grep -vE "Size: ($size_pattern)" "$ffuf_stripped" | awk -v d="$domain" '{print "https://" d "/" $1}' | sed 's#\([^:]\)//#\1/#g' > "$ffuf_clean"
      else
          awk -v d="$domain" '{print "https://" d "/" $1}' "$ffuf_stripped" | sed 's#\([^:]\)//#\1/#g' > "$ffuf_clean"
      fi
  fi

  # ====================================================================
  # БЛОК ГЛУБОКОЙ СОРТИРОВКИ (DEEP SORTING)
  # ====================================================================
  log "[INFO] Starting Deep Sorting of paths..."
  pushd "$outdir/PATHS" > /dev/null

    # 1. Агрегация всех сырых данных
    cat gau.txt katana.txt waybackpy.txt ffuf_clean.txt goofuzz.txt 2>/dev/null | sort -u > ALL_PATHS.txt

    if [ -s "ALL_PATHS.txt" ]; then
        # Регулярки для расширений (учитываем возможные параметры типа .js?v=1)
        local static_exts="jpg|jpeg|png|css|woff|woff2|svg|jsf"
        local js_exts="js"

        # 2. Выделяем JavaScript (включая .js?t=123)
        log "[INFO] Extracting JavaScript files..."
        grep -Ei "\.(${js_exts})(\?.*)?$" ALL_PATHS.txt > ALL_JS.txt || true
        sed -ri "/\.(${js_exts})(\?.*)?$/Id" ALL_PATHS.txt

        # 3. Выделяем Статику (включая .jpg?v=1)
        log "[INFO] Extracting static assets..."
        grep -Ei "\.(${static_exts})(\?.*)?$" ALL_PATHS.txt > ALL_STATIC.txt || true
        sed -ri "/\.(${static_exts})(\?.*)?$/Id" ALL_PATHS.txt

        # 4. Выделяем Параметры (всё, где остался '?', но уже без JS и статики)
        log "[INFO] Extracting endpoints with parameters..."
        grep -F "?" ALL_PATHS.txt > ALL_PARAMS.txt || true
        sed -i "/\?/d" ALL_PATHS.txt

        # 5. Финальная уникализация всех файлов
        for f in ALL_JS.txt ALL_STATIC.txt ALL_PARAMS.txt ALL_PATHS.txt; do
            if [ -f "$f" ]; then
                sort -u "$f" -o "$f"
                log "[DEBUG] Created $f ($(wc -l < "$f") lines)"
            fi
        done
    else
        log "[WARN] ALL_PATHS.txt is empty. Sorting skipped."
    fi
  popd > /dev/null

  log "[END] End Paths Enumeration"
}


run_vuln_scans(){
    log "[START] Start Targeted Vulnerability Scan (CMS/Specific)"
    if [ "$rate_limit_checked" = false ]; then check_rate_limit; fi
    if $rate_limit_block; then log "[CRIT] Rate Limit BLOCK. Skipping."; return; fi
    if [ "$target_cms" == "wp" ]; then
        log "[INFO] Podman WPScan..."
        local podman_cmd="podman run -it --rm --network host docker.io/wpscanteam/wpscan --rua --no-banner -e ap,at,cb,dbe,u,m,tt --url https://$domain"
        if [ -n "$WPSCAN_API_KEY" ] && [ "$WPSCAN_API_KEY" != "null" ]; then
            podman_cmd="$podman_cmd --api-token $WPSCAN_API_KEY"
        fi
        run_tool "wpscan_podman" "$podman_cmd" "$outdir/VULN_SCAN/wpscan.txt"
    fi
    log "[END] End Targeted Vulnerability Scan"
}

run_nmap(){
    log "[START] Running Nmap Scan..."
    local grep_file="$outdir/nmap.grep"
    local txt_file="$outdir/nmap.txt"
    if [ "$VPS_ENABLED" == "true" ]; then
        log "[INFO] Запуск Nmap через VPS ($VPS_SSH_STR)..."
        local nmap_cmd="ssh $VPS_SSH_STR \"$VPS_NMAP_PATH -Pn -sS --open -n -oG - $domain\""
        run_tool "nmap (VPS)" "$nmap_cmd" "$grep_file"
        if [ -s "$grep_file" ]; then
            log "[INFO] Formatting Nmap output to human-readable format..."
            awk '/Ports:/ { print "Target: " $2; print "Status: " $3; print "Open Ports:"; for (i=5; i<=NF; i++) { gsub(",", "", $i); split($i, a, "/"); if (a[2] == "open") { printf "  - %-9s %s (%s)\n", a[1]"/"a[3], a[2], a[5] } }; print "------------------------------------------------" }' "$grep_file" > "$txt_file"
        fi
    else
        run_tool "nmap" "nmap -Pn -sS --open -oG $grep_file -oN $txt_file $domain" "$txt_file"
    fi
    move_file "$txt_file" "$outdir/INFRA_SCAN/"
    move_file "$grep_file" "$outdir/LOGS/"
    log "[END] End Ports Scan"
}

# ====================================================================
# ФИНАЛЬНЫЙ ПОТОК
# ====================================================================
check_tools

if $do_subdomains; then
    run_subdomains_enumeration
fi

if $do_paths; then
    # Запускаем всегда, внутри разберемся что активно, что пассивно
    run_paths_enumeration
fi

if [ -n "$target_cms" ]; then
    # Внутри run_vuln_scans уже есть проверка: if $rate_limit_block; then return; fi
    # Так что оставляем как есть — wpscan не пойдет при блоке.
    run_vuln_scans
fi

if $do_ports; then
    run_nmap
fi

log "Ejecución finalizada. Results in: $outdir"