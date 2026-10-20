#!/bin/bash
# Web サービスの稼働確認。外側 (公開 URL) から内側 (コンテナ) へ順に確認し、障害の起きている層を絞り込む。
# 対象はすべて設定ファイルの checks.web_services で指定する。
# 使い方: checks/web_services.sh [--quiet] [-c CONFIG]

set -uo pipefail

source "$(dirname "$(readlink -f "$0")")/../lib/common.sh"
parse_common_args "$@"
load_config
if [[ ${#EXTRA_ARGS[@]} -gt 0 ]]; then
    echo "不明なオプション: ${EXTRA_ARGS[*]}" >&2
    exit 1
fi

mapfile -t OK_CODES < <(cfg_list CFG_checks_web_services_ok_codes)

# 応答コードで判定する。ok_codes 内なら OK、接続不可と 5xx は要対応、それ以外は要確認
check_url() {
    local label="$1" url="$2" timeout="$3" code
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$timeout" "$url" 2>/dev/null) || true
    code=${code:-000}
    if [[ "$code" == 000 ]]; then
        crit "${label}: 応答なし (${url})"
    elif code_in "$code" "${OK_CODES[@]+"${OK_CODES[@]}"}"; then
        ok "${label}: HTTP ${code} (${url})"
    elif [[ "$code" == 5* ]]; then
        crit "${label}: HTTP ${code} (${url})"
    else
        warn "${label}: HTTP ${code} (${url})"
    fi
}

# 並列配列 (CFG_x__label, CFG_x__url) の URL を順に確認する
check_url_list() {
    local prefix="$1" timeout="$2" i
    local -n _n="${prefix}__count" 2>/dev/null
    if [[ ! -v _n || "$_n" -eq 0 ]]; then
        info "設定なし"
        return
    fi
    local -n _labels="${prefix}__label" _urls="${prefix}__url"
    for ((i = 0; i < _n; i++)); do
        check_url "${_labels[i]:-${_urls[i]}}" "${_urls[i]}" "$timeout"
    done
}

# ==============================================================
# 1. 公開 URL (nginx 経由)
# ==============================================================
header "公開URL疎通確認"
check_url_list CFG_checks_web_services_public_urls 10

# ==============================================================
# 2. バックエンド (127.0.0.1 に直接。nginx や認証を経由しない)
# ==============================================================
header "バックエンド直接疎通確認"
check_url_list CFG_checks_web_services_backends 5

ES_URL="${CFG_checks_web_services_elasticsearch_url:-}"
if [[ -n "$ES_URL" ]]; then
    ES_HEALTH=$(curl -s --max-time 5 "${ES_URL%/}/_cluster/health" 2>/dev/null || true)
    if [[ -z "$ES_HEALTH" ]]; then
        crit "Elasticsearch: 応答なし (${ES_URL})"
    else
        ES_STATUS=$(echo "$ES_HEALTH" | jq -r '.status' 2>/dev/null || echo "unknown")
        case "$ES_STATUS" in
            green)  ok "Elasticsearch: クラスタ状態 green" ;;
            yellow) ok "Elasticsearch: クラスタ状態 yellow (シングルノード構成では正常)" ;;
            red)    crit "Elasticsearch: クラスタ状態 red" ;;
            *)      warn "Elasticsearch: クラスタ状態を判定できませんでした (${ES_STATUS})" ;;
        esac
    fi
fi

# ==============================================================
# 3. systemd サービス
# ==============================================================
header "systemd サービス状態"
mapfile -t SERVICES < <(cfg_list CFG_checks_web_services_systemd_services)
[[ ${#SERVICES[@]} -eq 0 ]] && info "設定なし"
for svc in "${SERVICES[@]+"${SERVICES[@]}"}"; do
    state=$(systemctl is-active "$svc" 2>/dev/null) || true
    if [[ "$state" == "active" ]]; then
        ok "${svc}: active"
    else
        crit "${svc}: ${state:-unknown} (クラッシュループの可能性。journalctl -u ${svc} で確認)"
    fi
done

# ==============================================================
# 4. 定期実行 (timer と、その前回の結果)
# ==============================================================
header "定期実行 (systemd timer)"
TIMER_N="${CFG_checks_web_services_timers__count:-0}"
[[ $TIMER_N -eq 0 ]] && info "設定なし"
for ((i = 0; i < TIMER_N; i++)); do
    timer="${CFG_checks_web_services_timers__timer[i]}"
    service="${CFG_checks_web_services_timers__service[i]:-${timer%.timer}.service}"
    if ! systemctl cat "$timer" &>/dev/null; then
        warn "${timer} が見つかりません"
        continue
    fi
    if systemctl is-active --quiet "$timer" 2>/dev/null; then
        ok "${timer}: 稼働中"
    else
        warn "${timer}: 停止中"
    fi
    result=$(systemctl show "$service" -p Result --value 2>/dev/null || echo "unknown")
    state=$(systemctl show "$service" -p ActiveState --value 2>/dev/null || echo "unknown")
    if [[ "$state" == "activating" || "$state" == "active" ]]; then
        info "${service}: 実行中 (前回結果チェックはスキップ)"
    elif [[ "$result" == "success" ]]; then
        ok "${service}: 前回実行は成功"
    else
        crit "${service}: 前回実行の結果が ${result}"
    fi
done

# ==============================================================
# 5. Docker コンテナ (docker-compose プロジェクト単位)
# ==============================================================
header "Docker コンテナ状態"
mapfile -t PROJECTS < <(cfg_list CFG_checks_web_services_docker_compose_projects)
mapfile -t ON_DEMAND < <(cfg_list CFG_checks_web_services_docker_on_demand_patterns)

is_on_demand() {
    local name="$1" pat
    for pat in "${ON_DEMAND[@]+"${ON_DEMAND[@]}"}"; do
        # shellcheck disable=SC2053  # パターンとして照合する
        [[ "$name" == $pat ]] && return 0
    done
    return 1
}

if [[ ${#PROJECTS[@]} -eq 0 ]]; then
    info "設定なし"
elif [[ $IS_ROOT -ne 1 ]]; then
    need_root "docker ps"
fi
for project in "${PROJECTS[@]+"${PROJECTS[@]}"}"; do
    [[ $IS_ROOT -eq 1 ]] || break
    if ! DOCKER_PS=$(docker ps -a --filter "label=com.docker.compose.project=${project}" \
            --format '{{.Names}}\t{{.State}}\t{{.Status}}' 2>&1); then
        warn "${project}: Docker コンテナ状態を取得できません: ${DOCKER_PS}"
        continue
    fi
    if [[ -z "$DOCKER_PS" ]]; then
        warn "${project}: docker-compose のコンテナが見つかりません"
        continue
    fi
    while IFS=$'\t' read -r name state status; do
        [[ -z "$name" ]] && continue
        # 必要なときだけ動かすコンテナは、常時稼働を想定しない。exit 0 なら正常終了として扱う
        if is_on_demand "$name"; then
            if [[ "$state" == "exited" ]]; then
                exit_code=$(echo "$status" | grep -oP '(?<=Exited \()[0-9]+(?=\))' || true)
                if [[ -z "$exit_code" || "$exit_code" == "0" ]]; then
                    info "${name}: ${status} (オンデマンド実行コンテナ)"
                else
                    crit "${name}: ${status}"
                fi
            else
                ok "${name}: ${status}"
            fi
            continue
        fi
        if [[ "$state" == "running" ]]; then
            ok "${name}: ${status}"
        else
            crit "${name}: ${state} (${status})"
        fi
    done <<< "$DOCKER_PS"
done

# ==============================================================
# まとめ
# ==============================================================
finish "すべてのサービスが正常に応答しています"
exit 0
