# ssc の各チェックで共通に使う関数。source して使う。
#   - 設定 (YAML) の読み込み: CFG_* 変数として展開される (lib/config.py を参照)
#   - 結果の出力: ok / info / warn / crit と、最後のまとめ (finish)
# 送信側 (lib/report.sh) は、まとめの行「要対応項目: N 件」か「問題なし」を見て件数を判定する。
# どちらも出ていなければ実行失敗とみなすので、チェックは必ず最後に finish を呼ぶこと。

SSC_HOME="${SSC_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

QUIET="${QUIET:-0}"
ISSUES=0
IS_ROOT=0
[[ $EUID -eq 0 ]] && IS_ROOT=1

header() { echo -e "\n${BOLD}${CYAN}=== $1 ===${RESET}"; }
ok()     { [[ $QUIET -eq 0 ]] && echo -e "  ${GREEN}[OK]${RESET} $1" || true; }
info()   { [[ $QUIET -eq 0 ]] && echo -e "  ${CYAN}[情報]${RESET} $1" || true; }
# QUIET でも常に表示する OK 行 (件数・使用量など、問題なしでも把握しておきたい数値向け)
ok_always() { echo -e "  ${GREEN}[OK]${RESET} $1"; }
warn()   { echo -e "  ${YELLOW}[要確認]${RESET} $1"; ISSUES=$((ISSUES+1)); }
crit()   { echo -e "  ${RED}[要対応]${RESET} $1"; ISSUES=$((ISSUES+1)); }
need_root() { info "$1: root 権限が必要なためスキップ (sudo で実行)"; }

# まとめを出力する。$1 = 問題がないときの文言、以降 = 問題があるときに続けて出す行
finish() {
    local ok_msg="$1"; shift
    echo ""
    echo -e "${BOLD}========================================${RESET}"
    if [[ $ISSUES -eq 0 ]]; then
        echo -e "${GREEN}${BOLD}  問題なし — ${ok_msg}${RESET}"
    else
        echo -e "${YELLOW}${BOLD}  要対応項目: ${ISSUES} 件${RESET}"
        local line
        for line in "$@"; do echo -e "$line"; done
    fi
    echo -e "${BOLD}========================================${RESET}"
}

load_config() {
    local out
    if ! out=$(python3 "${SSC_HOME}/lib/config.py" shell ${SSC_CONFIG:+-c "$SSC_CONFIG"}); then
        echo "ssc: 設定を読み込めませんでした" >&2
        exit 2
    fi
    eval "$out"
    STATE_DIR="${CFG_state_dir:-/var/lib/ssc}"
}

# 設定の配列を、未定義や空でも set -u で落ちずに展開する: cfg_list CFG_x | while read ...
cfg_list() {
    local -n _arr="$1" 2>/dev/null || return 0
    [[ -v _arr ]] || return 0
    printf '%s\n' "${_arr[@]+"${_arr[@]}"}" | sed '/^$/d'
}

# HTTP コードが ok_codes (例: 2xx, 401) に含まれるか
code_in() {
    local code="$1" pat; shift
    for pat in "$@"; do
        [[ "$pat" == "$code" ]] && return 0
        [[ "$pat" =~ ^([0-9])xx$ && "${code:0:1}" == "${BASH_REMATCH[1]}" ]] && return 0
    done
    return 1
}

# 引数の処理 (各チェック共通): --quiet / -c CONFIG と、チェック固有のオプションを $EXTRA_ARGS に残す
parse_common_args() {
    EXTRA_ARGS=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --quiet|-q) QUIET=1 ;;
            -c|--config) SSC_CONFIG="$2"; shift ;;
            *) EXTRA_ARGS+=("$1") ;;
        esac
        shift
    done
}
