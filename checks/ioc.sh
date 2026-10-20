#!/bin/bash
# IOC (侵害の痕跡) の一覧と、ログ・現在の接続を照合する。
# 一覧ファイルは checks.ioc.files で指定する (書式は examples/ioc/README.md)。
# 一度報告したログの行は state_dir/ioc_seen に記録し、次回からは「既報」として要対応に数えない
# (記録するのは ssc run から実行したときだけ。手動の実行では記録しない)。
# 使い方: checks/ioc.sh [--quiet] [-c CONFIG]

set -uo pipefail

source "$(dirname "$(readlink -f "$0")")/../lib/common.sh"
parse_common_args "$@"
load_config
if [[ ${#EXTRA_ARGS[@]} -gt 0 ]]; then
    echo "不明なオプション: ${EXTRA_ARGS[*]}" >&2
    exit 1
fi

ARGS=()
while IFS= read -r p; do ARGS+=(--ioc "$p"); done < <(cfg_list CFG_checks_ioc_files)
while IFS= read -r p; do ARGS+=(--log "$p"); done < <(cfg_list CFG_checks_ioc_logs)
[[ "${CFG_checks_ioc_check_connections:-1}" == 1 ]] && ARGS+=(--connections)
SEEN_FILE="${STATE_DIR}/ioc_seen"
ARGS+=(--state "$SEEN_FILE")
[[ "${SSC_RECORD_STATE:-0}" == 1 ]] && ARGS+=(--record)

[[ $IS_ROOT -ne 1 ]] && info "root 以外では読めないログがあるため、結果が不完全な可能性があります (sudo で実行)"

if ! RESULT=$(python3 "${SSC_HOME}/lib/ioc_match.py" "${ARGS[@]}"); then
    echo "ssc: IOC の照合に失敗しました" >&2
    exit 2
fi

header "IOC の一覧"
IOC_COUNT=$(grep -c '^IOC' <<< "$RESULT" || true)
if [[ $IOC_COUNT -eq 0 ]]; then
    warn "IOC が1件も読み込めませんでした (checks.ioc.files: $(cfg_list CFG_checks_ioc_files | paste -sd' '))"
else
    ok "IOC ${IOC_COUNT} 件 (IP $(grep -cP '^IOC\tip\t' <<< "$RESULT") / ドメイン $(grep -cP '^IOC\tdomain\t' <<< "$RESULT") / パス $(grep -cP '^IOC\tpath\t' <<< "$RESULT"))"
fi
while IFS=$'\t' read -r _ msg; do
    warn "$msg"
done < <(grep '^ERR' <<< "$RESULT")

header "ログとの照合"
LOG_HITS=0
while IFS=$'\t' read -r _ kind value source hits new success sample; do
    [[ $hits -eq 0 ]] && continue
    LOG_HITS=1
    if [[ $new -eq 0 ]]; then
        info "${value} (${source}): ${hits} 行 — すべて既報"
    elif [[ "$kind" == path && $success -eq 0 ]]; then
        warn "${value} (${source}): 新たに ${new} 行のリクエスト (成功応答なし)"
        echo "      例: ${sample}"
    else
        msg="新たに ${new} 行に出現"
        [[ $success -gt 0 ]] && msg+="、うち成功応答 ${success} 行"
        crit "${value} (${source}): ${msg}"
        echo "      例: ${sample}"
    fi
done < <(grep '^IOC' <<< "$RESULT")
[[ $LOG_HITS -eq 0 && $IOC_COUNT -gt 0 ]] && ok "どの IOC もログに出現していません"
LOG_LIST=$(cfg_list CFG_checks_ioc_logs | paste -sd' ')
info "対象: ${LOG_LIST}"

if [[ "${CFG_checks_ioc_check_connections:-1}" == 1 ]]; then
    header "現在の接続との照合"
    CONN=0
    while IFS=$'\t' read -r _ value source line; do
        crit "${value} (${source}) と通信中: ${line}"
        CONN=1
    done < <(grep '^CONN' <<< "$RESULT")
    [[ $CONN -eq 0 && $IOC_COUNT -gt 0 ]] && ok "IOC の IP との接続なし"
fi

finish "IOC の痕跡はありません"
exit 0
