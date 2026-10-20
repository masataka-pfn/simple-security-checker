# ssc (simple-security-checker) — Ubuntu サーバーのセキュリティ点検とメール通知

`ssc`（simple-security-checker）は、Ubuntu / Debian のサーバーを毎日自動で点検し、問題があればメールで知らせる Bash のツールです。
「攻撃される入口を持たない構成を保つ」ことを目的に、次の 4 つを点検します。

| チェック | 内容 |
| --- | --- |
| `security_updates` | 未適用のセキュリティ更新を CISA KEV（悪用実績）と FIRST EPSS（悪用確率）で評価。カーネル、needrestart、unattended-upgrades、証明書の期限、ディスクなども確認 |
| `attack_surface` | 許可していないポート、SSH の設定、Docker のポート公開、ufw、nginx の設定の残骸、`.env` などの公開ファイル、アカウントと鍵の変化（基準との差分） |
| `web_services` | 公開 URL → 127.0.0.1 のバックエンド → systemd → timer → Docker の順に稼働を確認 |
| `ioc` | 脅威レポートの IOC（IP・ドメイン・パス）を、ログと現在の接続と照合 |

自前のスクリプトも `external` として登録すれば、同じ仕組みで結果をメールで受け取れます。

## 必要なもの

- Ubuntu 22.04 / 24.04（Debian 系なら動く見込み）
- `python3-yaml`、`curl`、`jq`、`msmtp`（設定済みのもの）
- 任意: `needrestart`、`ufw`、`docker`、`nginx`（あるものだけ確認します）

## インストール

```bash
git clone https://github.com/masataka-pfn/simple-security-checker.git
cd simple-security-checker
sudo ./install.sh                    # /opt/ssc に配置し、/usr/local/sbin/ssc を作成
sudo editor /etc/ssc/config.yaml     # 送信先・監視対象・実行時刻を設定
sudo ssc config validate
sudo ssc init-baseline               # 攻撃点チェックの基準を作成
sudo ssc run security --dry-run      # 送らずにメールの内容を確認
sudo ssc install-cron                # 設定の schedule から /etc/cron.d/ssc を生成
```

## 設定

設定は `/etc/ssc/config.yaml` に書きます（`-c` か環境変数 `SSC_CONFIG` で別の場所も指定できます）。
書かなかった項目には [`config/defaults.yaml`](config/defaults.yaml) の既定値が使われ、`ssc config dump` で最終的な値を確認できます。
書き方の例は [`config/config.example.yaml`](config/config.example.yaml) を見てください。
設定ファイルは一般ユーザーでもチェックを実行できるよう誰でも読める権限（644）で置くので、パスワードなどの秘密は書かないでください（メールの認証情報は `~/.msmtprc` に置きます）。

自分のサーバー用の設定の元ファイルは、別の非公開リポジトリで管理するのがおすすめです（履歴とバックアップが残ります）。手元に置くだけでよければ、このリポジトリの `site/` も使えます。`site/` は `.gitignore` で除外してあるので、宛先やホスト名を書いても誤ってコミットされません。編集したら `sudo install -m 644 site/config.yaml /etc/ssc/config.yaml` などで `/etc/ssc` に反映します（cron は root で動くので、一般ユーザーが書き換えられる場所の設定を直接読ませないでください）。

### ジョブと通知方式

ジョブは「どのチェックを、いつ、どの方式で通知するか」の組です。

```yaml
jobs:
  security:
    check: security_updates
    schedule: "03:00"          # "HH:MM" (毎日) か cron 形式
    notify: calendar
  web-watch:
    check: web_services
    schedule: "*/5 * * * *"
    notify: change
  web-daily:
    check: web_services
    schedule: "05:30"
    notify: always
```

| notify | 送る条件 | 件名 |
| --- | --- | --- |
| `calendar` | 問題があればその日に送る。なければ `mail.weekly_day` の曜日だけ送る | `[要対応] … N件` / `[OK] … 週次サマリー` |
| `change` | 前回と状態（OK / NG / FAIL）が変わったときだけ送る | `[要対応] … N件` / `[復旧] …` |
| `always` | 毎回送る | `[要対応] … N件` / `[OK] …` |

本文には要確認・要対応の行だけを載せます。`always` のジョブだけは、何が正常だったかまで分かるよう OK の行も載せます（ジョブごとに `verbose: true` / `false` で変えられます）。

どの方式でも、チェックが途中で異常終了してまとめの行を出さなかった場合は `[実行失敗]` として必ず送ります。
「メールが来ない」ことが「問題なし」と「点検自体が壊れている」のどちらか分からなくなるのを防ぐためです。
同じ理由で、`change` の監視には毎朝 1 回の `always` を組み合わせるのがおすすめです。

### メール

```yaml
mail:
  to: [admin@example.com]
  run_as: ubuntu      # cron (root) から msmtp をこのユーザーとして実行する
```

msmtp は `~/.msmtprc` の持ち主と実行ユーザーが一致しないと送信を拒否します。cron は root で動くため、`run_as` に `.msmtprc` の持ち主を指定します。

## コマンド

| コマンド | 説明 |
| --- | --- |
| `ssc check <チェック名>\|all [--quiet]` | チェックを実行して表示する（メールは送らない）。`all` ですべてのチェック |
| `ssc run <ジョブ名>\|all [--force] [--dry-run]` | ジョブを実行し、通知方式に従って送る。`all` で有効なジョブをすべて実行 |
| `ssc list` | ジョブの一覧 |
| `ssc init-baseline` | 攻撃点チェックの基準（ログインユーザー、authorized_keys、sudo、ufw）を今の状態で保存する。意図した変更を受け入れるときにも使う |
| `ssc install-cron [--print]` | `/etc/cron.d/ssc` を生成する |
| `ssc config validate` / `dump` | 設定の検査 / 最終的な設定の表示 |

チェックは一般ユーザーでも実行できます。root が必要な項目は `[情報]` と表示して飛ばします。

## IOC の照合

脅威レポートの IOC を `/etc/ssc/ioc.d/*.txt` に置くと、翌日から毎日ログと照合します。
レポートの defang 表記（`38.244.50[.]120`）はそのまま貼り付けて構いません。書式は [`examples/ioc/README.md`](examples/ioc/README.md) を見てください。

## 実行時のファイル

| 場所 | 内容 |
| --- | --- |
| `/etc/ssc/config.yaml` | 設定 |
| `/etc/ssc/ioc.d/` | IOC の一覧 |
| `/var/lib/ssc/baseline/` | 攻撃点チェックの基準 |
| `/var/lib/ssc/state/<ジョブ名>` | 前回の状態（`change` 用） |
| `/var/lib/ssc/ioc_seen` | 報告済みの IOC の行 |
| `/var/lib/ssc/kev_catalog_cache.json` | CISA KEV のキャッシュ（24 時間） |

## 出力の約束

各チェックは結果を `[OK]` / `[情報]` / `[要確認]` / `[要対応]` の行で出し、最後に `要対応項目: N 件` か `問題なし — …` を出します。
`ssc run` はこのまとめの行で件数を判定します。`external` のコマンドも同じ行を出すか、`ok_pattern` / `issues_pattern` で書式を指定してください。

## ライセンス

[MIT](LICENSE)
