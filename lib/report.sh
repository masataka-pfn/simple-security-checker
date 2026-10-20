# ジョブ (設定ファイルの jobs.<名前>) を実行し、通知方式に従ってメールを送る。bin/ssc から source して使う。
#
# 通知方式 (jobs.<名前>.notify):
#   calendar : 問題があればその日に送る。なければ mail.weekly_day の曜日だけ週次サマリーを送る
#   change   : 前回と状態 (OK / NG / FAIL) が変わったときだけ送る。頻繁に実行しても同じ通知を繰り返さない
#   always   : 毎回送る (毎朝の定期報告など。届かないこと自体が異常の合図になる)
# どの方式でも、チェックがまとめの行を出さずに終わった場合は [実行失敗] として必ず送る。

# 件名に使う既定の名前
job_title() {
    case "$1" in
        security_updates) echo "セキュリティチェック" ;;
        attack_surface)   echo "攻撃点チェック" ;;
        web_services)     echo "Webサービス監視" ;;
        ioc)              echo "IOC チェック" ;;
        *)                echo "$1" ;;
    esac
}

# 件名を MIME エンコードする (日本語の件名が文字化けしないように)
encode_subject() {
    printf '=?UTF-8?B?%s?=' "$(printf '%s' "$1" | base64 -w0)"
}

send_mail() {
    local subject="$1" body="$2" dry_run="$3"
    local to from run_as
    to=$(cfg_list CFG_mail_to | paste -sd, | sed 's/,/, /g')
    from="${CFG_mail_from:-}"
    run_as="${CFG_mail_run_as:-}"
    local msg
    msg=$(
        echo "To: ${to}"
        [[ -n "$from" ]] && echo "From: ${from}"
        echo "Subject: $(encode_subject "$subject")"
        echo "MIME-Version: 1.0"
        echo "Content-Type: text/plain; charset=UTF-8"
        echo "Content-Transfer-Encoding: 8bit"
        echo ""
        echo "$body"
    )
    if [[ "$dry_run" == 1 ]]; then
        echo "----- 送信せずに表示 (--dry-run): ${subject} -----"
        echo "$msg"
        return 0
    fi
    # msmtp は ~/.msmtprc の持ち主と実行ユーザーが一致しないと拒否するため、
    # root で実行されたときは mail.run_as のユーザーとして送る
    if [[ $EUID -eq 0 && -n "$run_as" ]]; then
        runuser -u "$run_as" -- msmtp -t <<< "$msg"
    else
        msmtp -t <<< "$msg"
    fi
}

# ジョブを実行する: run_job <名前> <force 0|1> <dry_run 0|1>
run_job() {
    local name="$1" force="$2" dry_run="$3"
    local key="${name//[^A-Za-z0-9_]/_}"
    local check_var="CFG_jobs_${key}_check"
    if [[ -z "${!check_var:-}" ]]; then
        echo "ssc: ジョブがありません: ${name} (ssc list で一覧を表示)" >&2
        return 2
    fi
    local check="${!check_var}"
    local notify_var="CFG_jobs_${key}_notify" title_var="CFG_jobs_${key}_title"
    local notify="${!notify_var:-calendar}"
    # 本文に OK の行も載せるか。always (定期報告) は既定で載せ、何が正常だったかまで分かるようにする
    local verbose_var="CFG_jobs_${key}_verbose" verbose_default=0
    [[ "$notify" == always ]] && verbose_default=1
    local quiet_opt=--quiet
    [[ "${!verbose_var:-$verbose_default}" == 1 ]] && quiet_opt=""
    local default_title
    if [[ "$check" == external ]]; then default_title="$name"; else default_title=$(job_title "$check"); fi
    local title="${!title_var:-$default_title}"

    # ---- チェックを実行して出力を集める ----
    local output rc=0
    if [[ "$check" == external ]]; then
        local cmd_var="CFG_jobs_${key}_command" log_var="CFG_jobs_${key}_log"
        local cmd="${!cmd_var}" log_pat="${!log_var:-}"
        if [[ -n "$log_pat" ]]; then
            # 結果をログファイルに書くコマンド: 今回追記された分だけを読む (log は date の書式で日付を埋め込める)
            local log_file pre_size
            log_file=$(date +"$log_pat")
            pre_size=$(stat -c %s "$log_file" 2>/dev/null || echo 0)
            bash -c "$cmd" >/dev/null 2>&1 || rc=$?
            output=$(tail -c "+$((pre_size + 1))" "$log_file" 2>/dev/null || echo "(ログを読めません: ${log_file})")
        else
            output=$(bash -c "$cmd" 2>&1) || rc=$?
        fi
    else
        local record=1
        [[ "$dry_run" == 1 ]] && record=0
        output=$(SSC_RECORD_STATE=$record bash "${SSC_HOME}/checks/${check}.sh" $quiet_opt ${SSC_CONFIG:+-c "$SSC_CONFIG"} 2>&1) || rc=$?
    fi
    output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output")

    # ---- 結果を判定する (まとめの行がなければ実行失敗) ----
    # 外部コマンドで書式が違う場合は jobs.<名前>.ok_pattern / issues_pattern (grep -P) で指定する
    local ok_pat_var="CFG_jobs_${key}_ok_pattern" issues_pat_var="CFG_jobs_${key}_issues_pattern"
    local ok_pat="${!ok_pat_var:-^\s*問題なし}" issues_pat="${!issues_pat_var:-要対応項目: \K[0-9]+}"
    local status issues=0
    issues=$(grep -oP "$issues_pat" <<< "$output" | tail -1)
    if [[ -n "$issues" && "$issues" != 0 ]]; then
        status=NG
    elif [[ "$issues" == 0 ]] || grep -qP "$ok_pat" <<< "$output"; then
        status=OK
        issues=0
    else
        status=FAIL
        output="チェックがまとめの行を出さずに終了しました (終了コード ${rc})。途中で異常終了した可能性があります。"$'\n\n'"${output}"
    fi

    # ---- 送るかどうかを決める ----
    local host date tag="" state_file prev=""
    host="${CFG_mail_host_label:-$(hostname -f 2>/dev/null || hostname)}"
    date=$(date '+%Y-%m-%d %H:%M')
    state_file="${STATE_DIR}/state/${name}"
    [[ -f "$state_file" ]] && prev=$(cat "$state_file")

    case "$status" in
        FAIL) tag="[実行失敗]" ;;
        NG)   tag="[要対応]" ;;
    esac
    if [[ "$status" == OK ]]; then
        case "$notify" in
            calendar)
                if [[ "$force" == 1 || "$(date +%u)" == "${CFG_mail_weekly_day:-1}" ]]; then
                    tag="[OK]"
                fi ;;
            change)
                if [[ -n "$prev" && "$prev" != OK ]]; then
                    tag="[復旧]"
                elif [[ "$force" == 1 ]]; then
                    tag="[OK]"
                fi ;;
            always) tag="[OK]" ;;
        esac
    elif [[ "$notify" == change && "$status" == "$prev" && "$force" != 1 ]]; then
        tag=""   # 異常が続いている間は再送しない
    fi

    local sent=0
    if [[ -n "$tag" ]]; then
        local subject="${tag} ${host} ${title}"
        case "$status" in
            NG) subject+=": ${issues}件" ;;
            OK) [[ "$tag" == "[OK]" && "$notify" == calendar ]] && subject+=" 週次サマリー" ;;
        esac
        subject+=" (${date})"
        send_mail "$subject" "$output" "$dry_run" || return 1
        sent=1
    fi

    # 状態は送信に成功したとき (または送る必要がなかったとき) だけ更新する。失敗したら次回に再送される
    if [[ "$dry_run" != 1 ]]; then
        mkdir -p -m 700 "${STATE_DIR}/state" 2>/dev/null && echo "$status" > "$state_file"
    fi
    [[ "$dry_run" == 1 && $sent -eq 0 ]] && echo "(送信条件に当たらないため送信しません: 状態 ${status}、通知方式 ${notify})"
    return 0
}
