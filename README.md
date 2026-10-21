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

ジョブには次の項目も書けます。

| 項目 | 内容 |
| --- | --- |
| `title` | 件名に使う名前（省略時はチェックの名前、`external` ならジョブ名） |
| `verbose` | `true` で本文に OK の行も載せる（既定は `notify: always` のときだけ `true`） |
| `enabled` | `false` にすると cron に登録せず、`ssc run all` でも実行しない |

本文には要確認・要対応の行だけを載せます。`always` のジョブだけは、何が正常だったかまで分かるよう OK の行も載せます（ジョブごとに `verbose: true` / `false` で変えられます）。

どの方式でも、チェックが途中で異常終了してまとめの行を出さなかった場合は `[実行失敗]` として必ず送ります。
「メールが来ない」ことが「問題なし」と「点検自体が壊れている」のどちらか分からなくなるのを防ぐためです。
同じ理由で、`change` の監視には毎朝 1 回の `always` を組み合わせるのがおすすめです。

### 自前のスクリプトを登録する（external）

```yaml
jobs:
  my-check:
    check: external
    command: /usr/local/bin/my_check.sh --quiet
    log: /var/log/my_check/%Y%m%d.log   # 結果をファイルに書くコマンドなら、その場所 (date の書式)。省略時は標準出力
    schedule: "04:00"
    notify: calendar
    # ok_pattern: '^All checks passed'    # まとめの行の書式が違うときだけ (grep -P)
    # issues_pattern: 'Issues: \K[0-9]+'
```

`log` を指定すると、実行の前後で増えた分だけを結果として読みます。
スクリプト自身の設定（除外する IP の一覧など）は、ssc ではなくそのスクリプトの側で管理してください。

### メール

```yaml
mail:
  to: [admin@example.com]
  run_as: ubuntu      # cron (root) から msmtp をこのユーザーとして実行する
  # from: ssc@example.com     # 省略時は msmtp の設定に従う
  # host_label: web-01        # 件名の先頭に付ける名前。省略時は hostname -f
  # weekly_day: 1             # calendar の週次サマリーを送る曜日 (1=月曜 ... 7=日曜)
```

msmtp は `~/.msmtprc` の持ち主と実行ユーザーが一致しないと送信を拒否します。cron は root で動くため、`run_as` に `.msmtprc` の持ち主を指定します。

### チェックごとの主な設定

`checks.<チェック名>` に書きます。すべての項目と既定値は [`config/defaults.yaml`](config/defaults.yaml) にあります。

| チェック | 主な項目 |
| --- | --- |
| `security_updates` | `epss_threshold`（要確認にする EPSS の値）、`regression_packages`、`cert_warn_days` / `cert_crit_days`、`disk_warn_pct` / `disk_crit_pct`、`update_lists` |
| `attack_surface` | `allowed_tcp_ports` / `allowed_udp_ports`、`extra_sensitive_paths`（外から読めてはいけないパスの追加分）、`url_check`、`nginx_conf_globs` |
| `web_services` | `public_urls`、`backends`、`ok_codes`、`systemd_services`、`timers`、`docker_compose_projects`、`docker_on_demand_patterns`、`elasticsearch_url` |
| `ioc` | `files`（IOC の一覧）、`logs`（照合するログ）、`check_connections` |

アクセスログで新しく狙われたパスを見つけたら、`sensitive_paths` を書き直さずに `extra_sensitive_paths` に足していくと、既定のリストの更新も受け取れます。

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
| `/etc/cron.d/ssc` | `ssc install-cron` が生成する cron の設定 |
| `/var/lib/ssc/baseline/` | 攻撃点チェックの基準 |
| `/var/lib/ssc/state/<ジョブ名>` | 前回の状態（`change` 用） |
| `/var/lib/ssc/ioc_seen` | 報告済みの IOC の行 |
| `/var/lib/ssc/kev_catalog_cache.json` | CISA KEV のキャッシュ（24 時間） |

## 出力の約束

各チェックは結果を `[OK]` / `[情報]` / `[要確認]` / `[要対応]` の行で出し、最後に `要対応項目: N 件` か `問題なし — …` を出します。
`ssc run` はこのまとめの行で件数を判定します。`external` のコマンドも同じ行を出すか、`ok_pattern` / `issues_pattern` で書式を指定してください。

## ライセンス

[MIT](LICENSE)
