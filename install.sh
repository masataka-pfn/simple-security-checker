#!/bin/bash
# ssc をインストールする: sudo ./install.sh [--prefix /opt/ssc]
# 既存の /etc/ssc/config.yaml は上書きしない。cron の登録は設定を書いてから ssc install-cron で行う。
set -euo pipefail

PREFIX=/opt/ssc
while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix) PREFIX="$2"; shift 2 ;;
        -h|--help) echo "使い方: sudo $0 [--prefix DIR]"; exit 0 ;;
        *) echo "不明なオプション: $1" >&2; exit 1 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "root で実行してください (sudo $0)" >&2
    exit 1
fi

SRC="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"

missing=()
python3 -c 'import yaml' 2>/dev/null || missing+=(python3-yaml)
for c in curl jq msmtp; do command -v "$c" &>/dev/null || missing+=("$c"); done
if [[ ${#missing[@]} -gt 0 ]]; then
    echo "必要なパッケージがありません: ${missing[*]}"
    echo "  sudo apt install ${missing[*]}"
    exit 1
fi

install -d -m 755 "$PREFIX"
cp -r "$SRC/bin" "$SRC/lib" "$SRC/checks" "$SRC/config" "$SRC/examples" "$PREFIX/"
chmod 755 "$PREFIX/bin/ssc" "$PREFIX"/checks/*.sh
ln -sf "$PREFIX/bin/ssc" /usr/local/sbin/ssc

install -d -m 755 /etc/ssc /etc/ssc/ioc.d
if [[ ! -f /etc/ssc/config.yaml ]]; then
    install -m 640 "$SRC/config/config.example.yaml" /etc/ssc/config.yaml
    echo "/etc/ssc/config.yaml を作成しました (サンプルのまま。編集してください)"
fi
install -d -m 700 /var/lib/ssc

echo "インストールしました: $PREFIX (コマンド: /usr/local/sbin/ssc)"
cat <<'NEXT'

次の手順:
  1. sudo editor /etc/ssc/config.yaml          # 送信先・監視対象・実行時刻を設定
  2. sudo ssc config validate
  3. sudo ssc init-baseline                    # 攻撃点チェックの基準を作成
  4. sudo ssc run <ジョブ名> --dry-run          # 送らずに内容を確認
  5. sudo ssc install-cron                     # /etc/cron.d/ssc を生成
NEXT
