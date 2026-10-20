#!/usr/bin/env python3
"""ssc の設定ファイル (YAML) を読み、Bash から eval できる変数定義に変換する。

  config.py shell    [-c CONFIG]   変数定義を出力 (lib/common.sh が eval する)
  config.py validate [-c CONFIG]   設定の誤りを検査して表示
  config.py dump     [-c CONFIG]   既定値をマージした最終的な設定を YAML で表示

変換規則 (キーの英数字以外は _ に置き換える):
  scalar            -> CFG_a_b='v'          (true/false は 1/0、null は空文字)
  list of scalars   -> CFG_a_b=('v1' 'v2')
  list of mappings  -> CFG_a_b__<field>=(...) をフィールドごとの並列配列で、件数は CFG_a_b__count
  mapping           -> 子要素を再帰的に出力し、元のキー一覧を CFG_a_b__keys=(...) に出力
"""
import argparse
import os
import re
import shlex
import sys

try:
    import yaml
except ImportError:
    sys.stderr.write("ssc: PyYAML が必要です (sudo apt install python3-yaml)\n")
    sys.exit(2)

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULTS = os.path.join(HERE, "..", "config", "defaults.yaml")
DEFAULT_CONFIG = "/etc/ssc/config.yaml"

CHECKS = {"security_updates", "attack_surface", "web_services", "ioc", "external"}
NOTIFY = {"calendar", "change", "always"}
SCHEDULE_HHMM = re.compile(r"^([01]?\d|2[0-3]):([0-5]\d)$")
CRON_FIELD = re.compile(r"^[\d*/,\-A-Za-z]+$")


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except PermissionError:
        sys.stderr.write(f"ssc: {path} を読む権限がありません "
                         f"(sudo で実行するか、sudo chmod 644 {path} で読めるようにしてください)\n")
    except yaml.YAMLError as e:
        sys.stderr.write(f"ssc: {path} の YAML に誤りがあります:\n{e}\n")
    sys.exit(2)


def merge(base, over):
    """mapping は再帰的にマージし、それ以外 (list を含む) は上書きする。"""
    if isinstance(base, dict) and isinstance(over, dict):
        out = dict(base)
        for k, v in over.items():
            out[k] = merge(base.get(k), v) if k in base else v
        return out
    return over


def var(path):
    return "CFG_" + "_".join(re.sub(r"[^A-Za-z0-9_]", "_", str(p)) for p in path)


def scalar(v):
    if v is None:
        return ""
    if isinstance(v, bool):
        return "1" if v else "0"
    return str(v)


def emit(node, path, out):
    if isinstance(node, dict):
        out.append(f"{var(path)}__keys=({' '.join(shlex.quote(str(k)) for k in node)})")
        for k, v in node.items():
            emit(v, path + [k], out)
    elif isinstance(node, list):
        if node and all(isinstance(x, dict) for x in node):
            fields = []
            for item in node:
                fields += [k for k in item if k not in fields]
            out.append(f"{var(path)}__count={len(node)}")
            for fld in fields:
                vals = " ".join(shlex.quote(scalar(item.get(fld))) for item in node)
                out.append(f"{var(path + [''])}_{re.sub(r'[^A-Za-z0-9_]', '_', fld)}=({vals})")
        else:
            out.append(f"{var(path)}=({' '.join(shlex.quote(scalar(x)) for x in node)})")
    else:
        out.append(f"{var(path)}={shlex.quote(scalar(node))}")


def validate(cfg):
    errors = []
    mail = cfg.get("mail") or {}
    if not mail.get("to"):
        errors.append("mail.to: 送信先を1つ以上指定してください")
    jobs = cfg.get("jobs") or {}
    if not jobs:
        errors.append("jobs: ジョブが1つもありません")
    for name, job in jobs.items():
        where = f"jobs.{name}"
        if not re.fullmatch(r"[A-Za-z0-9_-]+", str(name)):
            errors.append(f"{where}: ジョブ名は英数字・_・- のみ使えます")
        if name == "all":
            errors.append(f"{where}: all は ssc run all で使う予約語なのでジョブ名にできません")
        if not isinstance(job, dict):
            errors.append(f"{where}: mapping で指定してください")
            continue
        if job.get("check") not in CHECKS:
            errors.append(f"{where}.check: {sorted(CHECKS)} のいずれかを指定してください")
        if job.get("notify", "calendar") not in NOTIFY:
            errors.append(f"{where}.notify: {sorted(NOTIFY)} のいずれかを指定してください")
        sched = str(job.get("schedule", ""))
        if sched and not SCHEDULE_HHMM.match(sched):
            fields = sched.split()
            if len(fields) != 5 or not all(CRON_FIELD.match(f) for f in fields):
                errors.append(f"{where}.schedule: \"HH:MM\" か cron 形式 (5 フィールド) で指定してください")
        if job.get("check") == "external" and not job.get("command"):
            errors.append(f"{where}.command: check: external には command が必要です")
    return errors


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["shell", "validate", "dump"])
    ap.add_argument("-c", "--config", default=os.environ.get("SSC_CONFIG", DEFAULT_CONFIG))
    args = ap.parse_args()

    cfg = load(DEFAULTS)
    if os.path.exists(args.config):
        cfg = merge(cfg, load(args.config))
    elif args.action != "dump":
        sys.stderr.write(f"ssc: 設定ファイルがありません: {args.config}\n")
        sys.exit(2)

    if args.action == "dump":
        yaml.safe_dump(cfg, sys.stdout, allow_unicode=True, sort_keys=False)
    elif args.action == "validate":
        errors = validate(cfg)
        for e in errors:
            print(f"エラー: {e}")
        if errors:
            sys.exit(1)
        print(f"OK: {args.config}")
    else:
        out = [f"CFG__file={shlex.quote(os.path.abspath(args.config))}"]
        emit(cfg, [], out)
        print("\n".join(out))


if __name__ == "__main__":
    main()
