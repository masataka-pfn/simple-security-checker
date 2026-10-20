#!/bin/bash
# 攻撃点（外部からの入口）の増加チェック
# 「あるべき状態」からのずれを検出する。外部の脅威情報には依存しない。
#   1. 外部に開いているポート / SSH 設定
#   2. Docker のポート公開
#   3. ufw ルール (基準との差分)
#   4. 公開してはいけないファイル (nginx 設定の残骸 / URL / ファイルシステム)
#   5. アカウントと鍵 (基準との差分)
# 基準 (baseline) は --init-baseline (ssc init-baseline) で作成・更新する (root 必須)。
# 使い方: checks/attack_surface.sh [--quiet] [--init-baseline] [-c CONFIG]

set -uo pipefail

source "$(dirname "$(readlink -f "$0")")/../lib/common.sh"
parse_common_args "$@"
load_config

INIT_BASELINE=0
for a in "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}"; do
    case "$a" in
        --init-baseline) INIT_BASELINE=1 ;;
        *) echo "不明なオプション: $a" >&2; exit 1 ;;
    esac
done

BASELINE_DIR="${STATE_DIR}/baseline"
INIT_CMD="sudo ssc init-baseline"

# ---- 設定 ----
mapfile -t ALLOWED_TCP_PORTS < <(cfg_list CFG_checks_attack_surface_allowed_tcp_ports)
mapfile -t ALLOWED_UDP_PORTS < <(cfg_list CFG_checks_attack_surface_allowed_udp_ports)
mapfile -t SENSITIVE_PATHS < <(cfg_list CFG_checks_attack_surface_sensitive_paths; cfg_list CFG_checks_attack_surface_extra_sensitive_paths)
CHECK_UA="${CFG_checks_attack_surface_user_agent:-attack-surface-self-check}"
URL_CHECK="${CFG_checks_attack_surface_url_check:-1}"
mapfile -t _GLOBS < <(cfg_list CFG_checks_attack_surface_nginx_conf_globs)
NGINX_CONF_GLOBS=()
for g in "${_GLOBS[@]+"${_GLOBS[@]}"}"; do
    for f in $g; do NGINX_CONF_GLOBS+=("$f"); done
done
# sites-enabled に置かれていたら読み込まれてしまうバックアップ類のファイル名
STRAY_CONF_RE='(\.(bak|old|orig|save|swp|tmp|dpkg-[a-z]+|ucf-[a-z]+)|~)$|\.bak\.|\.[0-9]{8,}$'

# ==============================================================
# 基準と比較する項目の収集 (出力はソート済みの行)
# ==============================================================
csort() { LC_ALL=C sort -u | sed '/^$/d'; }

collect_login_users() {
    awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1" uid="$3" shell="$7}' /etc/passwd | csort
}

collect_authorized_keys() {
    local user home f
    while read -r user _; do
        home=$(getent passwd "$user" | cut -d: -f6)
        for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
            [[ -f "$f" ]] || continue
            ssh-keygen -lf "$f" 2>/dev/null | sed "s|^|${user} ($(basename "$f")): |"
        done
    done < <(collect_login_users)
    true
}

collect_sudo() {
    local g members f
    for g in sudo admin wheel; do
        members=$(getent group "$g" | cut -d: -f4)
        [[ -n "$(getent group "$g")" ]] && echo "group ${g}: ${members}"
    done
    for f in /etc/sudoers /etc/sudoers.d/*; do
        [[ -f "$f" ]] || continue
        echo "file ${f}: $(sha256sum "$f" | cut -c1-16)"
    done
}

collect_ufw_rules() {
    ufw status 2>/dev/null | awk 'f{print} /^--/{f=1}' | sed -E 's/[[:space:]]+/ /g; s/ $//'
}

BASELINE_ITEMS=(login_users authorized_keys sudo ufw_rules)

# ==============================================================
# --init-baseline: 現在の状態を基準として保存して終了
# ==============================================================
if [[ $INIT_BASELINE -eq 1 ]]; then
    if [[ $IS_ROOT -ne 1 ]]; then
        echo "--init-baseline は root で実行してください (${INIT_CMD})"
        exit 1
    fi
    mkdir -p -m 700 "$BASELINE_DIR"
    for item in "${BASELINE_ITEMS[@]}"; do
        "collect_${item}" | csort > "${BASELINE_DIR}/${item}"
        echo "  ${item}: $(wc -l < "${BASELINE_DIR}/${item}") 件を保存"
    done
    echo "基準を保存しました: ${BASELINE_DIR}"
    exit 0
fi

compare_baseline() {
    local item="$1" label="$2"
    local file="${BASELINE_DIR}/${item}"
    # state_dir は root 専用 (700) なので、一般ユーザーには基準の有無そのものが見えない。
    # その場合は「基準がない」ではなく root が必要としてスキップする
    if [[ -e "$STATE_DIR" && ( ! -x "$STATE_DIR" || ( -d "$BASELINE_DIR" && ! -r "$BASELINE_DIR" ) ) ]]; then
        need_root "${label} (基準との比較)"
        return
    fi
    if [[ ! -f "$file" ]]; then
        warn "${label}: 基準がありません (${INIT_CMD} で作成)"
        return
    fi
    local current added removed
    current=$("collect_${item}" | csort)
    added=$(LC_ALL=C comm -13 "$file" <(echo "$current") | sed '/^$/d')
    removed=$(LC_ALL=C comm -23 "$file" <(echo "$current") | sed '/^$/d')
    if [[ -z "$added" && -z "$removed" ]]; then
        ok "${label}: 基準と一致 ($(echo "$current" | sed '/^$/d' | wc -l) 件)"
        return
    fi
    while IFS= read -r line; do
        [[ -n "$line" ]] && crit "${label}: 追加 — ${line}"
    done <<< "$added"
    while IFS= read -r line; do
        [[ -n "$line" ]] && warn "${label}: 削除 — ${line}"
    done <<< "$removed"
    info "${label}: 意図した変更なら ${INIT_CMD} で基準を更新"
}

# ==============================================================
# 1. 外部に開いているポート / SSH 設定
# ==============================================================
header "外部に開いているポート"

is_local_addr() {
    [[ "$1" =~ ^127\. || "$1" =~ ^\[::1\] || "$1" =~ ^\[::ffff:127\. || "$1" == *%lo* ]]
}

check_listeners() {
    local proto="$1"; shift
    local -a allowed=("$@")
    local flag found=0
    [[ "$proto" == tcp ]] && flag="-ltnH" || flag="-lunH"
    [[ $IS_ROOT -eq 1 ]] && flag="${flag}p"
    while read -r _ _ _ local_addr _ proc; do
        [[ -z "$local_addr" ]] && continue
        local addr="${local_addr%:*}" port="${local_addr##*:}"
        is_local_addr "$addr" && continue
        found=1
        local p allowed_port=0
        for p in "${allowed[@]}"; do [[ "$port" == "$p" ]] && allowed_port=1; done
        local who
        who=$(echo "$proc" | grep -oP 'users:\(\("\K[^"]+' || true)
        if [[ $allowed_port -eq 1 ]]; then
            ok "${proto}/${port} (${addr}${who:+, ${who}})"
        else
            crit "${proto}/${port} が外部で待ち受けています (${addr}${who:+, ${who}})。許可リスト外"
        fi
    done < <(ss $flag 2>/dev/null | sort -u)
    [[ $found -eq 0 ]] && ok "${proto}: 外部で待ち受けているポートなし"
}

check_listeners tcp "${ALLOWED_TCP_PORTS[@]+"${ALLOWED_TCP_PORTS[@]}"}"
check_listeners udp "${ALLOWED_UDP_PORTS[@]+"${ALLOWED_UDP_PORTS[@]}"}"

header "SSH 設定"
if [[ $IS_ROOT -ne 1 ]]; then
    need_root "sshd -T"
elif ! SSHD_T=$(sshd -T 2>/dev/null); then
    warn "sshd -T の実行に失敗しました"
else
    sshd_val() { echo "$SSHD_T" | awk -v k="$1" '$1==k{print $2; exit}'; }
    case "$(sshd_val permitrootlogin)" in
        no)                                ok "PermitRootLogin no" ;;
        prohibit-password|without-password) info "PermitRootLogin prohibit-password (鍵認証のみ root ログイン可)" ;;
        *)                                 crit "PermitRootLogin $(sshd_val permitrootlogin) (パスワードで root ログイン可能)" ;;
    esac
    if [[ "$(sshd_val passwordauthentication)" == "yes" ]]; then
        warn "PasswordAuthentication yes (パスワード認証が有効)"
    else
        ok "PasswordAuthentication no"
    fi
    if [[ "$(sshd_val kbdinteractiveauthentication)" == "yes" && "$(sshd_val usepam)" == "yes" ]]; then
        warn "KbdInteractiveAuthentication yes + UsePAM yes (PAM 経由でパスワード認証が可能)"
    fi
fi

# ==============================================================
# 2. Docker のポート公開 (Docker は ufw をすり抜ける)
# ==============================================================
header "Docker のポート公開"

if ! command -v docker &>/dev/null; then
    info "docker が見つかりません"
elif [[ $IS_ROOT -ne 1 ]]; then
    need_root "docker ps"
elif ! DOCKER_PORTS=$(docker ps --format '{{.Names}}\t{{.Ports}}' 2>&1); then
    warn "docker ps の実行に失敗しました: ${DOCKER_PORTS}"
else
    EXPOSED=0
    while IFS=$'\t' read -r name ports; do
        [[ -z "$name" ]] && continue
        pub=$(echo "$ports" | tr ',' '\n' | grep -E '(0\.0\.0\.0|\[?::\]?):[0-9]+->' | sed 's/^ *//' || true)
        if [[ -n "$pub" ]]; then
            crit "${name}: 全インターフェースに公開 — $(echo "$pub" | paste -sd' ') (ufw では防げません。127.0.0.1: に限定してください)"
            EXPOSED=1
        fi
    done <<< "$DOCKER_PORTS"
    [[ $EXPOSED -eq 0 ]] && ok "外部に公開しているコンテナなし (すべて 127.0.0.1 か非公開)"
fi

# ==============================================================
# 3. ufw ルール
# ==============================================================
header "ufw ルール"

if ! command -v ufw &>/dev/null; then
    warn "ufw が見つかりません"
elif [[ $IS_ROOT -ne 1 ]]; then
    need_root "ufw status"
else
    UFW_VERBOSE=$(ufw status verbose 2>/dev/null)
    if echo "$UFW_VERBOSE" | grep -q '^Status: active'; then
        ok "ufw: active"
    else
        crit "ufw が無効です"
    fi
    if echo "$UFW_VERBOSE" | grep -qE '^Default:.*deny \(incoming\)'; then
        ok "既定ポリシー: incoming を拒否"
    else
        crit "既定ポリシーが incoming 拒否になっていません: $(echo "$UFW_VERBOSE" | grep '^Default:')"
    fi
    compare_baseline ufw_rules "ufw 許可ルール"
fi

# ==============================================================
# 4. 公開してはいけないファイル
# ==============================================================
header "nginx 設定の残骸"

STRAY=0
for f in /etc/nginx/sites-enabled/*; do
    [[ -e "$f" ]] || continue
    if basename "$f" | grep -qE "$STRAY_CONF_RE"; then
        crit "sites-enabled にバックアップらしきファイル: ${f} (nginx は sites-enabled/* をすべて読み込むため、古い設定が有効になり得ます。sites-enabled の外へ移動してください)"
        STRAY=1
    fi
done
[[ $STRAY -eq 0 ]] && ok "sites-enabled にバックアップ類のファイルなし"

if [[ $IS_ROOT -eq 1 ]]; then
    CONFLICTS=$(nginx -t 2>&1 | grep -oP 'conflicting server name "\K[^"]+" on [^,]+' | sort -u || true)
    if [[ -n "$CONFLICTS" ]]; then
        while IFS= read -r c; do
            warn "server_name の重複: \"${c} (後から読まれた側の server ブロックは無視されています)"
        done <<< "$CONFLICTS"
    else
        ok "server_name の重複なし"
    fi
else
    need_root "nginx -t (server_name の重複確認)"
fi

header "公開してはいけないファイル (URL)"

# nginx 設定から server_name とロケーションの先頭パスを取り出す
NGINX_CONFS=()
for f in "${NGINX_CONF_GLOBS[@]+"${NGINX_CONF_GLOBS[@]}"}"; do [[ -f "$f" ]] && NGINX_CONFS+=("$f"); done

if [[ "$URL_CHECK" != 1 ]]; then
    info "URL チェックは無効 (checks.attack_surface.url_check)"
elif ! command -v curl &>/dev/null; then
    warn "curl が見つからないため URL チェックをスキップ"
elif [[ ${#NGINX_CONFS[@]} -eq 0 ]]; then
    info "nginx の設定ファイルが見つかりません"
else
    mapfile -t HOSTS < <(grep -hoP '^\s*server_name\s+\K[^;]+' "${NGINX_CONFS[@]}" 2>/dev/null \
        | tr ' \t' '\n\n' | grep -vE '^(_|)$|[*~]' | sort -u)
    PUBLIC_IP=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
    [[ -n "$PUBLIC_IP" ]] && HOSTS+=("$PUBLIC_IP")
    mapfile -t PREFIXES < <(grep -hoP '^\s*location\s+(=\s*|\^~\s*)?\K/[^\s{]*' "${NGINX_CONFS[@]}" 2>/dev/null \
        | sed -E 's#^(/[^/]*).*#\1#; /^\/$/d' | sort -u)

    BODY=$(mktemp)
    trap 'rm -f "$BODY"' EXIT

    # 公開 DNS やヘアピン NAT に依存しないよう、ホスト名は 127.0.0.1 に解決させて nginx を直接叩く。
    # 証明書の不一致は攻撃者も無視できるので -k を付ける。
    # 静的ファイルなら Range が効いて 206 が返るので、大きなファイルも先頭 64KB だけ取得する。
    probe() {
        local scheme="$1" host="$2" path="$3" out
        out=$(curl -sk -A "$CHECK_UA" --max-time 10 -r 0-65535 \
            --resolve "${host}:443:127.0.0.1" --resolve "${host}:80:127.0.0.1" \
            -o "$BODY" -w '%{http_code}\t%{content_type}\t%{size_download}' \
            "${scheme}://${host}${path}" 2>/dev/null) || true
        IFS=$'\t' read -r P_CODE P_CTYPE P_SIZE <<< "$out"
        P_CODE=${P_CODE:-000}
    }

    # パスの種類ごとに「中身が本物か」を判定する
    looks_leaked() {
        local path="$1"
        case "$path" in
            */.env*)             grep -qE '^[A-Za-z_][A-Za-z0-9_]*=' "$BODY" ;;
            */.git/config)       grep -q '^\[core\]' "$BODY" ;;
            */.git/HEAD)         grep -q '^ref: ' "$BODY" ;;
            */.htpasswd)         grep -qE '^[^:<[:space:]]+:[$!*{]' "$BODY" ;;
            *.sql)               grep -qiE 'CREATE TABLE|INSERT INTO|DROP TABLE' "$BODY" ;;
            *docker-compose.yml) grep -qE '^(services|version):' "$BODY" ;;
            */credentials)       grep -q 'aws_access_key_id' "$BODY" ;;
            */id_rsa)            grep -q 'PRIVATE KEY' "$BODY" ;;
            */.claude/*.json|*/.mcp.json) grep -qE '"(permissions|env|hooks|mcpServers)"' "$BODY" ;;
            */CLAUDE.md)         grep -qE '^#' "$BODY" ;;
            *)                   return 1 ;;
        esac
    }

    TOTAL=0
    for host in "${HOSTS[@]}"; do
        for scheme in https http; do
            HOST_ISSUES=0
            HOST_TOTAL=0
            probe "$scheme" "$host" "/"
            if [[ "$P_CODE" == 000 ]]; then
                info "${scheme}://${host}: 接続できないためスキップ"
                continue
            fi
            for prefix in "" "${PREFIXES[@]}"; do
                # 存在しないパスへの応答 (ソフト404) を基準として記録
                probe "$scheme" "$host" "${prefix}/zz-surface-check-${RANDOM}${RANDOM}"
                SOFT_CODE="$P_CODE"
                for path in "${SENSITIVE_PATHS[@]}"; do
                    url_path="${prefix}${path}"
                    probe "$scheme" "$host" "$url_path"
                    HOST_TOTAL=$((HOST_TOTAL+1))
                    case "$P_CODE" in
                        200|206) ;;
                        *) continue ;;
                    esac
                    if [[ "$P_CODE" == 206 ]]; then
                        crit "${scheme}://${host}${url_path} が読めます (HTTP 206: 静的ファイルとして存在)"
                    elif looks_leaked "$url_path"; then
                        crit "${scheme}://${host}${url_path} が読めます (HTTP 200、中身が本物の形式)"
                    elif [[ "$P_CTYPE" == text/html* && "$SOFT_CODE" == 200 ]]; then
                        continue   # 存在しないパスにも 200 の HTML を返すアプリ (ソフト404)
                    else
                        warn "${scheme}://${host}${url_path}: HTTP ${P_CODE} (${P_CTYPE:-不明}, ${P_SIZE} bytes)。存在しないパスへの応答は HTTP ${SOFT_CODE}"
                    fi
                    HOST_ISSUES=$((HOST_ISSUES+1))
                done
            done
            TOTAL=$((TOTAL+HOST_TOTAL))
            [[ $HOST_TOTAL -gt 0 && $HOST_ISSUES -eq 0 ]] && ok "${scheme}://${host}: ${HOST_TOTAL} 件すべて読めない"
        done
    done
    info "対象: ホスト ${#HOSTS[@]} 件 × http/https × パス先頭 $(( ${#PREFIXES[@]} + 1 )) 種 × ファイル ${#SENSITIVE_PATHS[@]} 種 (計 ${TOTAL} リクエスト、UA: ${CHECK_UA})"
fi

header "公開してはいけないファイル (公開ディレクトリ)"

if [[ ${#NGINX_CONFS[@]} -gt 0 ]]; then
    mapfile -t WEB_PATHS < <(grep -hoP '^\s*(root|alias)\s+\K[^;\s]+' "${NGINX_CONFS[@]}" 2>/dev/null \
        | grep -v '\$' | sort -u)
    FS_FOUND=0
    for p in "${WEB_PATHS[@]}"; do
        [[ -e "$p" ]] || continue
        while IFS= read -r hit; do
            [[ -z "$hit" ]] && continue
            crit "公開ディレクトリに置かれています: ${hit}"
            FS_FOUND=1
        done < <(find "$p" -xdev \( -name '.env*' -o -name '.git' -o -name '.svn' -o -name '.htpasswd' \
                -o -name '.claude' -o -name 'CLAUDE.md' -o -name '.mcp.json' \
                -o -name '*.bak' -o -name '*.old' -o -name '*.orig' -o -name '*.save' -o -name '*.swp' -o -name '*~' \
                -o -name '*.sql' -o -name '*.sql.gz' -o -name '*.dump' \
                -o -name '*.zip' -o -name '*.tar' -o -name '*.tar.gz' -o -name '*.tgz' -o -name '*.7z' \
                -o -name '*.pem' -o -name '*.key' -o -name 'id_rsa*' -o -name 'id_ed25519*' \) \
                -print -prune 2>/dev/null | head -20)
    done
    [[ $FS_FOUND -eq 0 ]] && ok "root/alias の ${#WEB_PATHS[@]} 箇所に危険なファイルなし"
fi

# ==============================================================
# 5. アカウントと鍵
# ==============================================================
header "アカウントと鍵"

UID0=$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd)
if [[ -n "$UID0" ]]; then
    crit "root 以外に UID 0 のアカウント: $(echo "$UID0" | paste -sd' ')"
else
    ok "UID 0 は root のみ"
fi

compare_baseline login_users "ログイン可能なアカウント"

if [[ $IS_ROOT -eq 1 ]]; then
    EMPTY_PW=$(awk -F: '$2==""{print $1}' /etc/shadow)
    if [[ -n "$EMPTY_PW" ]]; then
        crit "パスワードが空のアカウント: $(echo "$EMPTY_PW" | paste -sd' ')"
    else
        ok "パスワードが空のアカウントなし"
    fi
    compare_baseline authorized_keys "SSH 公開鍵 (authorized_keys)"
    compare_baseline sudo "sudo 権限"
else
    need_root "shadow / authorized_keys / sudoers の確認"
fi

# ==============================================================
# まとめ
# ==============================================================
finish "攻撃点の増加はありません"
exit 0
