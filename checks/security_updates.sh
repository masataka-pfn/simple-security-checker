#!/bin/bash
# セキュリティアップデートとサーバーの健全性の確認 (Ubuntu/Debian)
# 使い方: checks/security_updates.sh [--quiet] [--update] [-c CONFIG]

set -euo pipefail

source "$(dirname "$(readlink -f "$0")")/../lib/common.sh"
parse_common_args "$@"
load_config

UPDATE_LISTS="${CFG_checks_security_updates_update_lists:-0}"
for a in "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}"; do
    case "$a" in
        --update|-u) UPDATE_LISTS=1 ;;
        --no-update) UPDATE_LISTS=0 ;;
        *) echo "不明なオプション: $a" >&2; exit 1 ;;
    esac
done

# ---- apt-get update (root のときのみ。一般ユーザーでは古いリストのまま確認する) ----
if [[ $UPDATE_LISTS -eq 1 ]]; then
    if [[ $IS_ROOT -eq 1 ]]; then
        echo -e "${CYAN}>>> パッケージリストを更新中...${RESET}"
        apt-get update -qq
    else
        echo -e "${CYAN}>>> パッケージリストの更新は root のときのみ行います (スキップ)${RESET}"
    fi
fi

# KEV カタログのキャッシュ置き場。state_dir に書けないとき (一般ユーザーで手動実行) は ~/.cache を使う
CACHE_DIR="$STATE_DIR"
if ! mkdir -p "$CACHE_DIR" 2>/dev/null || [[ ! -w "$CACHE_DIR" ]]; then
    CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/ssc"
    mkdir -p "$CACHE_DIR"
fi

REBOOT_REQUIRED=0

# ==============================================================
# 1. OS・カーネル情報
# ==============================================================
header "システム基本情報"
# lsb_release は Ubuntu 24.04 で非推奨のため /etc/os-release を直接参照
OS_DESC=$(. /etc/os-release && echo "$PRETTY_NAME")
echo -e "  OS      : ${OS_DESC}"
echo -e "  起動中  : $(uname -r)"
echo -e "  日時    : $(date '+%Y-%m-%d %H:%M %Z')"
LIST_AGE=$(( ( $(date +%s) - $(stat -c %Y /var/cache/apt/pkgcache.bin 2>/dev/null || echo 0) ) / 3600 ))
if [[ $LIST_AGE -gt 24 ]]; then
    warn "パッケージリストが ${LIST_AGE}h 前の状態 (--update で更新可)"
else
    ok "パッケージリスト: ${LIST_AGE}h 前に更新済み"
fi

# ==============================================================
# 2. カーネル更新状況
# ==============================================================
header "カーネル"
RUNNING=$(uname -r)
# インストール済みカーネルの中で最新を取得
LATEST_INSTALLED=$(dpkg -l 'linux-image-*-generic' 2>/dev/null \
    | awk '/^ii/{print $2}' \
    | grep -oP '\d+\.\d+\.\d+-\d+' \
    | sort -V | tail -1)

if [[ -z "$LATEST_INSTALLED" ]]; then
    warn "インストール済みカーネルを検出できませんでした"
else
    RUNNING_VER=$(echo "$RUNNING" | grep -oP '\d+\.\d+\.\d+-\d+')
    if [[ "$RUNNING_VER" != "$LATEST_INSTALLED" ]]; then
        # 文字列一致でなく sort -V でバージョン大小を判定
        NEWER=$(printf '%s\n%s\n' "$RUNNING_VER" "$LATEST_INSTALLED" | sort -V | tail -1)
        if [[ "$NEWER" == "$LATEST_INSTALLED" ]]; then
            crit "再起動が必要: 起動中=${RUNNING_VER}  インストール済み最新=${LATEST_INSTALLED}"
            REBOOT_REQUIRED=1
        else
            warn "起動中カーネルがインストール済みより新しい (ダウングレード環境?): ${RUNNING_VER} > ${LATEST_INSTALLED}"
        fi
    else
        ok "最新カーネルで起動中 (${RUNNING_VER})"
    fi
fi

# 古いカーネルイメージの数
OLD_KERNELS=$(dpkg -l 'linux-image-[0-9]*-generic' 2>/dev/null \
    | awk '/^ii/{print $2}' \
    | grep -v "$(uname -r | sed 's/-generic//')" \
    | wc -l)
if [[ $OLD_KERNELS -gt 1 ]]; then
    warn "古いカーネルイメージが ${OLD_KERNELS} 個残存 (sudo apt autoremove --purge で削除可)"
else
    ok "古いカーネルイメージ: ${OLD_KERNELS} 個"
fi

# ==============================================================
# 3. アップグレード可能パッケージ
# ==============================================================
header "アップグレード可能パッケージ"

# apt-get --simulate 結果をキャッシュ（同じコマンドを複数回実行しない）
APT_SIMULATE=$(apt-get --simulate upgrade 2>/dev/null)
APT_FULL_SIMULATE=$(apt-get --simulate full-upgrade 2>/dev/null)

UPGRADABLE=$(echo "$APT_SIMULATE" | grep '^Inst' || true)
UPGRADE_COUNT=$(echo "$UPGRADABLE" | grep -c '^Inst' || true)

# セキュリティアップデートとその他を区別 (-security リポジトリ由来でフィルタ)
SEC_UPGRADABLE=$(echo "$UPGRADABLE" | grep -i '\-security' || true)
SEC_COUNT=$(echo "$SEC_UPGRADABLE" | grep -c '^Inst' || true)
OTHER_UPGRADABLE=$(echo "$UPGRADABLE" | grep -iv '\-security' || true)
OTHER_COUNT=$(echo "$OTHER_UPGRADABLE" | grep -c '^Inst' || true)

# フォーマット: Inst <pkg> [<old>] (<new> <channel> [<arch>])
_print_pkg_list() {
    echo "$1" | awk '{
        pkg = $2; old = ""; new = ""
        match($0, /\[([^\]]+)\]/, a); if (a[1]) old = a[1]
        match($0, /\(([^ ]+)/, b);   if (b[1]) new = b[1]
        printf "    %-38s %-40s -> %s\n", pkg, old, new
    }'
}

if [[ $UPGRADE_COUNT -eq 0 ]]; then
    ok "アップグレード可能パッケージなし"
else
    if [[ $SEC_COUNT -gt 0 ]]; then
        crit "セキュリティアップデート ${SEC_COUNT} 件が未適用"
        _print_pkg_list "$SEC_UPGRADABLE"
    fi
    if [[ $OTHER_COUNT -gt 0 ]]; then
        info "その他のアップデート ${OTHER_COUNT} 件 (セキュリティ以外、通常は自動適用待ちで問題なし)"
        if [[ $QUIET -eq 0 ]]; then
            _print_pkg_list "$OTHER_UPGRADABLE"
        fi
    fi
fi

# full-upgrade でのみ適用されるパッケージ (保留分)
FULLUPGRADE=$(echo "$APT_FULL_SIMULATE" | grep '^Inst' || true)
NORMAL_PKGS=$(echo "$UPGRADABLE" | grep -oP '(?<=^Inst )\S+' || true)
EXTRA_COUNT=0
EXTRA_PKGS=""
# $FULLUPGRADE が空のとき while が空行で1回回るのを防ぐ
if [[ -n "$FULLUPGRADE" ]]; then
    while IFS= read -r line; do
        pkg=$(echo "$line" | grep -oP '(?<=^Inst )\S+' || true)
        if [[ -n "$pkg" ]] && ! echo "$NORMAL_PKGS" | grep -q "^${pkg}$"; then
            EXTRA_PKGS="${EXTRA_PKGS}\n    ${pkg}"
            EXTRA_COUNT=$((EXTRA_COUNT+1))
        fi
    done <<< "$FULLUPGRADE"
fi

if [[ $EXTRA_COUNT -gt 0 ]]; then
    warn "full-upgrade のみで適用される保留パッケージ: ${EXTRA_COUNT} 件 (依存関係変更を伴う)"
    echo -e "$EXTRA_PKGS"
else
    ok "保留パッケージなし"
fi

# ==============================================================
# 4. アップデート重要度評価 (CISA KEV / FIRST EPSS)
# ==============================================================
header "アップデート重要度評価 (CISA KEV / FIRST EPSS)"

KEV_CACHE="${CACHE_DIR}/kev_catalog_cache.json"
KEV_URL="${CFG_checks_security_updates_kev_url}"
KEV_CACHE_TTL_HOURS="${CFG_checks_security_updates_kev_cache_ttl_hours:-24}"
EPSS_THRESHOLD="${CFG_checks_security_updates_epss_threshold:-0.04}"
KEV_AVAILABLE=0
EPSS_JSON=""

# 保留中のセキュリティアップデートについて、changelog の版数差分から
# 対象バージョン範囲に含まれる CVE 番号を抽出する
extract_new_cves() {
    local pkg="$1" old_ver="$2" changelog cur_ver in_range=0 line
    changelog=$(timeout 15 apt-get changelog "$pkg" 2>/dev/null) || return 1
    [[ -z "$changelog" ]] && return 1
    while IFS= read -r line; do
        if [[ "$line" =~ ^[a-zA-Z0-9.+-]+\ \(([^\)]+)\) ]]; then
            cur_ver="${BASH_REMATCH[1]}"
            if dpkg --compare-versions "$cur_ver" gt "$old_ver"; then
                in_range=1
            else
                in_range=0
            fi
        fi
        [[ $in_range -eq 1 ]] && echo "$line" | grep -oP 'CVE-[0-9]{4}-[0-9]+' || true
    done <<< "$changelog" | sort -u
}

fetch_kev_catalog() {
    if [[ -f "$KEV_CACHE" ]]; then
        local age=$(( ( $(date +%s) - $(stat -c %Y "$KEV_CACHE" 2>/dev/null || echo 0) ) / 3600 ))
        if [[ $age -lt $KEV_CACHE_TTL_HOURS ]]; then
            KEV_AVAILABLE=1
            return 0
        fi
    fi
    if curl -fsSL --max-time 15 "$KEV_URL" -o "${KEV_CACHE}.tmp" 2>/dev/null && [[ -s "${KEV_CACHE}.tmp" ]]; then
        mv "${KEV_CACHE}.tmp" "$KEV_CACHE"
        KEV_AVAILABLE=1
    else
        rm -f "${KEV_CACHE}.tmp"
        # 取得に失敗しても古いキャッシュが残っていればそれを使う
        [[ -f "$KEV_CACHE" ]] && KEV_AVAILABLE=1
    fi
}

is_in_kev() {
    local cve="$1"
    [[ $KEV_AVAILABLE -eq 1 ]] || return 1
    jq -e --arg c "$cve" '.vulnerabilities[] | select(.cveID == $c)' "$KEV_CACHE" &>/dev/null
}

fetch_epss() {
    local cve_csv="$1"
    EPSS_JSON=$(curl -fsSL --max-time 15 "https://api.first.org/data/v1/epss?cve=${cve_csv}" 2>/dev/null) || return 1
    [[ -n "$EPSS_JSON" ]]
}

get_epss_score() {
    local cve="$1"
    echo "$EPSS_JSON" | jq -r --arg c "$cve" '.data[]? | select(.cve==$c) | .epss' 2>/dev/null
}

if [[ $SEC_COUNT -eq 0 ]]; then
    ok "評価対象のセキュリティアップデートなし"
elif ! command -v curl &>/dev/null || ! command -v jq &>/dev/null; then
    info "curl/jq が無いため重要度評価をスキップします (sudo apt install curl jq で導入可)"
else
    fetch_kev_catalog
    [[ $KEV_AVAILABLE -eq 0 ]] && info "CISA KEV カタログを取得できませんでした (オフライン?) — KEV判定はスキップします"

    declare -A PKG_CVES=()
    ALL_CVES=""
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        pkg=$(echo "$line" | awk '{print $2}')
        old_ver=$(echo "$line" | grep -oP '(?<=\[)[^\]]+' | head -1 || true)
        [[ -z "$old_ver" ]] && continue
        cves=$(extract_new_cves "$pkg" "$old_ver" || true)
        if [[ -n "$cves" ]]; then
            PKG_CVES["$pkg"]="$cves"
            ALL_CVES="${ALL_CVES}${cves}"$'\n'
        fi
    done <<< "$SEC_UPGRADABLE"
    ALL_CVES=$(echo "$ALL_CVES" | grep -v '^$' | sort -u || true)

    if [[ -z "$ALL_CVES" ]]; then
        info "changelog から CVE 番号を特定できませんでした (重要度評価は対象なし)"
    else
        CVE_CSV=$(echo "$ALL_CVES" | paste -sd, -)
        fetch_epss "$CVE_CSV" || info "FIRST EPSS の取得に失敗しました — EPSS判定はスキップします"

        for pkg in "${!PKG_CVES[@]}"; do
            for cve in ${PKG_CVES[$pkg]}; do
                if is_in_kev "$cve"; then
                    crit "${pkg}: ${cve} — CISA KEV カタログに掲載 (悪用実績あり、最優先で対応)"
                    continue
                fi
                score=$(get_epss_score "$cve")
                if [[ -n "$score" ]] && awk -v s="$score" -v t="$EPSS_THRESHOLD" 'BEGIN{exit !(s>=t)}'; then
                    warn "${pkg}: ${cve} — EPSSスコア ${score} (悪用可能性あり、対応推奨)"
                elif [[ -n "$score" ]]; then
                    ok "${pkg}: ${cve} — EPSSスコア ${score} (悪用可能性は低)"
                else
                    info "${pkg}: ${cve} — EPSS評価情報を取得できませんでした"
                fi
            done
        done
    fi
fi

# ==============================================================
# 5. セキュリティ回帰チェック（changelog）
# ==============================================================
header "セキュリティ回帰チェック"

# インストール済み libssl パッケージを動的に検出（将来の libssl3.5 等にも対応）
mapfile -t _INSTALLED_SSL < <(dpkg -l 'libssl*' 2>/dev/null | awk '/^ii/{print $2}' | grep -E '^libssl[0-9]')
# チェック対象: Web・暗号・ネットワーク関連の主要パッケージ
mapfile -t SEC_PKGS < <(cfg_list CFG_checks_security_updates_regression_packages)
SEC_PKGS+=("${_INSTALLED_SSL[@]+"${_INSTALLED_SSL[@]}"}")

for pkg in "${SEC_PKGS[@]+"${SEC_PKGS[@]}"}"; do
    dpkg -l "$pkg" 2>/dev/null | grep -q '^ii' || continue

    PKG_VER=$(dpkg -l "$pkg" 2>/dev/null | awk '/^ii/{print $3; exit}')
    CHANGELOG="/usr/share/doc/${pkg}/changelog.Debian.gz"
    [[ -f "$CHANGELOG" ]] || continue

    # 最新エントリ（最初の " -- maintainer" 行まで）を取得
    # awk が早期 exit すると zcat が SIGPIPE で終了するため pipefail を一時無効化
    set +o pipefail
    LATEST=$(zcat "$CHANGELOG" 2>/dev/null | awk '/^ -- /{found++} found==1{exit} {print}')
    set -o pipefail

    if echo "$LATEST" | grep -qiE 'SECURITY[[:space:]]+REGRESSION'; then
        CVELIST=$(echo "$LATEST" | grep -oP 'CVE-[0-9]+-[0-9]+' | sort -u | tr '\n' ' ')
        DETAIL=$(echo "$LATEST" | grep -iE 'SECURITY[[:space:]]+REGRESSION' | head -1 | sed 's/^[[:space:]]*//')

        # CVE-2026-49975 固有: HTTP/2 無効化が唯一の緩和策
        if echo "$CVELIST" | grep -q 'CVE-2026-49975'; then
            if grep -rqE '\bhttp2\b' /etc/nginx/ 2>/dev/null; then
                HTTP2_FILES=$(grep -rlE '\bhttp2\b' /etc/nginx/ 2>/dev/null | tr '\n' ' ')
                crit "${pkg} (${PKG_VER}): セキュリティ回帰 — ${CVELIST}"
                echo -e "      ${DETAIL}"
                echo -e "      ${RED}→ HTTP/2 が有効: ${HTTP2_FILES}${RESET}"
                echo -e "        緩和策: listen ... http2 を削除するか limit_req を追加"
            else
                ok "${pkg} (${PKG_VER}): セキュリティ回帰 ${CVELIST}— HTTP/2 無効で緩和済み"
            fi
        else
            crit "${pkg} (${PKG_VER}): セキュリティ回帰 — ${CVELIST:-パッチ無効化}"
            echo -e "      ${DETAIL}"
            if echo "$LATEST" | grep -qiE 'disabled|reverted|backed[[:space:]]+out|not[[:space:]]+applied'; then
                echo -e "      ${RED}→ パッチ自体が無効化されており、既知の緩和策なし(上流の修正版待ち)${RESET}"
            else
                echo -e "      ${YELLOW}→ 緩和策の有無は個別に要確認${RESET}"
            fi
        fi
    else
        ok "${pkg} (${PKG_VER}): changelog 最新エントリに回帰なし"
    fi
done

# ==============================================================
# 6. 再起動が必要なサービス (needrestart)
# ==============================================================
header "サービス再起動チェック"
if command -v needrestart &>/dev/null; then
    # || true ではなく ; true で needrestart の非ゼロ終了コードを明示的に無視
    NR_OUT=$(needrestart -b 2>/dev/null; true)
    SVCCOUNT=$(echo "$NR_OUT" | grep -c '^NEEDRESTART-SVC:' || true)
    if [[ $SVCCOUNT -gt 0 ]]; then
        warn "${SVCCOUNT} 個のサービスが再起動を必要としています"
        echo "$NR_OUT" | grep '^NEEDRESTART-SVC:' | sed 's/^NEEDRESTART-SVC: /    /'
    else
        ok "再起動が必要なサービスなし"
    fi
    # カーネルチェック (needrestartの観点)
    NR_KSTA=$(echo "$NR_OUT" | grep '^NEEDRESTART-KSTA:' | awk '{print $2}' || true)
    if [[ "$NR_KSTA" == "1" ]]; then
        ok "needrestart: カーネルは最新 (再起動不要)"
    elif [[ "$NR_KSTA" == "2" ]]; then
        crit "needrestart: カーネル更新あり — 再起動を推奨"
        REBOOT_REQUIRED=1
    fi
else
    warn "needrestart がインストールされていません (sudo apt install needrestart で導入可)"
fi

# Ubuntu 標準の再起動フラグ (/var/run/reboot-required) — needrestart を補完
if [[ -f /var/run/reboot-required ]]; then
    REBOOT_PKGS=""
    [[ -f /var/run/reboot-required.pkgs ]] && REBOOT_PKGS=$(tr '\n' ' ' < /var/run/reboot-required.pkgs)
    crit "再起動が必要です (/var/run/reboot-required)"
    [[ -n "$REBOOT_PKGS" ]] && echo "    対象パッケージ: ${REBOOT_PKGS}"
    REBOOT_REQUIRED=1
else
    ok "再起動フラグなし (/var/run/reboot-required 不在)"
fi

# ==============================================================
# 7. 自動更新 (unattended-upgrades)
# ==============================================================
header "自動更新 (unattended-upgrades)"
if systemctl is-active --quiet unattended-upgrades 2>/dev/null; then
    ok "unattended-upgrades: 動作中"
else
    warn "unattended-upgrades: 停止中"
fi

# ==============================================================
# 8. dpkg 整合性チェック
# ==============================================================
header "dpkg 整合性チェック"
DPKG_AUDIT=$(dpkg --audit 2>/dev/null || true)
if [[ -n "$DPKG_AUDIT" ]]; then
    crit "dpkg 不整合が検出されました"
    echo "$DPKG_AUDIT" | sed 's/^/    /'
else
    ok "dpkg: 整合性に問題なし"
fi

# ==============================================================
# 9. Snap パッケージ更新確認
# ==============================================================
if command -v snap &>/dev/null; then
    header "Snap パッケージ"
    SNAP_LIST=$(snap refresh --list 2>/dev/null | tail -n +2 || true)
    if [[ -n "$SNAP_LIST" ]]; then
        SNAP_COUNT=$(echo "$SNAP_LIST" | wc -l)
        warn "Snap パッケージに ${SNAP_COUNT} 件の更新があります"
        echo "$SNAP_LIST" | sed 's/^/    /'
    else
        ok "Snap パッケージ: 更新なし"
    fi
fi

# ==============================================================
# 10. ファイアウォール状態 (ufw)
# ==============================================================
if command -v ufw &>/dev/null; then
    header "ファイアウォール (ufw)"
    UFW_STATUS=$(ufw status 2>/dev/null | head -1 || true)
    if echo "$UFW_STATUS" | grep -q 'inactive'; then
        warn "ufw ファイアウォールが無効です"
    else
        ok "ufw: ${UFW_STATUS}"
    fi
fi

# ==============================================================
# 11. systemd 失敗ユニット
# ==============================================================
header "systemd 失敗ユニット"
FAILED_UNITS=$(systemctl --failed --no-legend --plain 2>/dev/null || true)
if [[ -n "$FAILED_UNITS" ]]; then
    FAILED_UNIT_COUNT=$(echo "$FAILED_UNITS" | wc -l)
    crit "systemd ユニットが ${FAILED_UNIT_COUNT} 件失敗しています"
    echo "$FAILED_UNITS" | awk '{print "    "$1" ("$3"/"$4")"}'
else
    ok "systemd: 失敗ユニットなし"
fi

# ==============================================================
# 12. SSL証明書の有効期限 (Let's Encrypt)
# ==============================================================
if [[ -d /etc/letsencrypt/live ]]; then
    header "SSL証明書 有効期限"
    CERT_WARN_DAYS="${CFG_checks_security_updates_cert_warn_days:-30}"
    CERT_CRIT_DAYS="${CFG_checks_security_updates_cert_crit_days:-7}"
    shopt -s nullglob
    CERTS=(/etc/letsencrypt/live/*/cert.pem)
    shopt -u nullglob
    if [[ ${#CERTS[@]} -eq 0 ]]; then
        info "Let's Encrypt証明書ディレクトリはありますが証明書が見つかりません"
    else
        for cert in "${CERTS[@]}"; do
            DOMAIN=$(basename "$(dirname "$cert")")
            ENDDATE=$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2)
            if [[ -z "$ENDDATE" ]]; then
                warn "${DOMAIN}: 証明書の有効期限を取得できませんでした"
                continue
            fi
            END_EPOCH=$(date -d "$ENDDATE" +%s)
            NOW_EPOCH=$(date +%s)
            DAYS_LEFT=$(( (END_EPOCH - NOW_EPOCH) / 86400 ))
            if [[ $DAYS_LEFT -lt $CERT_CRIT_DAYS ]]; then
                crit "${DOMAIN}: 証明書の有効期限まで残り ${DAYS_LEFT} 日"
            elif [[ $DAYS_LEFT -lt $CERT_WARN_DAYS ]]; then
                warn "${DOMAIN}: 証明書の有効期限まで残り ${DAYS_LEFT} 日"
            else
                ok "${DOMAIN}: 証明書の有効期限まで残り ${DAYS_LEFT} 日"
            fi
        done
    fi
fi

# ==============================================================
# 13. ログイン失敗・不正アクセス試行
# ==============================================================
header "ログイン失敗・不正アクセス試行"
FAILED_LOGIN_COUNT=0
if [[ -f /var/log/auth.log ]]; then
    FAILED_LOGIN_COUNT=$(grep -c 'Failed password' /var/log/auth.log 2>/dev/null || true)
elif command -v journalctl &>/dev/null; then
    FAILED_LOGIN_COUNT=$(journalctl -u ssh -u sshd --since "24 hours ago" 2>/dev/null | grep -c 'Failed password' || true)
fi
FAILED_LOGIN_COUNT=${FAILED_LOGIN_COUNT:-0}

FAILED_LOGIN_THRESHOLD="${CFG_checks_security_updates_failed_login_threshold:-20}"
if [[ $FAILED_LOGIN_COUNT -ge $FAILED_LOGIN_THRESHOLD ]]; then
    warn "直近24時間のログイン失敗: ${FAILED_LOGIN_COUNT} 件 (ブルートフォースの可能性)"
else
    ok_always "直近24時間のログイン失敗: ${FAILED_LOGIN_COUNT} 件"
fi

if command -v fail2ban-client &>/dev/null; then
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        BAN_COUNT=$(fail2ban-client status sshd 2>/dev/null | grep -oP 'Currently banned:\s*\K[0-9]+' || echo 0)
        ok "fail2ban: 動作中 (sshd 現在のBAN数: ${BAN_COUNT})"
    else
        warn "fail2ban はインストール済みですが停止中です"
    fi
else
    info "fail2ban がインストールされていません (sudo apt install fail2ban で導入可)"
fi

# ==============================================================
# 14. ディスク使用状況
# ==============================================================
header "ディスク使用状況"
DISK_WARN_PCT="${CFG_checks_security_updates_disk_warn_pct:-80}"
DISK_CRIT_PCT="${CFG_checks_security_updates_disk_crit_pct:-90}"
DISK_LINES=$(df -hPl -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | tail -n +2)
if [[ -z "$DISK_LINES" ]]; then
    warn "ディスク使用状況を取得できませんでした"
else
    while IFS= read -r line; do
        USE_PCT=$(echo "$line" | awk '{print $5}' | tr -d '%')
        MOUNT=$(echo "$line" | awk '{print $6}')
        SIZE=$(echo "$line" | awk '{print $2}')
        USED=$(echo "$line" | awk '{print $3}')
        AVAIL=$(echo "$line" | awk '{print $4}')
        if [[ "$USE_PCT" -ge $DISK_CRIT_PCT ]]; then
            crit "${MOUNT}: ${USE_PCT}% 使用中 (${USED}/${SIZE}, 空き ${AVAIL})"
        elif [[ "$USE_PCT" -ge $DISK_WARN_PCT ]]; then
            warn "${MOUNT}: ${USE_PCT}% 使用中 (${USED}/${SIZE}, 空き ${AVAIL})"
        else
            ok_always "${MOUNT}: ${USE_PCT}% 使用中 (${USED}/${SIZE}, 空き ${AVAIL})"
        fi
    done <<< "$DISK_LINES"
fi

# ==============================================================
# まとめ
# ==============================================================
if [[ $REBOOT_REQUIRED -eq 1 ]]; then
    echo -e "\n  ${RED}${BOLD}再起動: [更新が必要]${RESET}"
else
    echo -e "\n  ${GREEN}${BOLD}再起動: [更新は不要]${RESET}"
fi
ADVICE=("" "  ${BOLD}推奨コマンド:${RESET}" "    sudo apt-get update && sudo apt-get upgrade")
[[ $EXTRA_COUNT -gt 0 ]] && ADVICE+=("    sudo apt-get full-upgrade   # 依存関係変更を伴う保留パッケージ ${EXTRA_COUNT} 件を適用")
ADVICE+=("    sudo apt-get autoremove --purge")
[[ $REBOOT_REQUIRED -eq 1 ]] && ADVICE+=("    sudo reboot   # カーネル更新を適用する")
finish "すべてのチェックをパスしました" "${ADVICE[@]}"
exit 0
