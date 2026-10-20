#!/usr/bin/env python3
"""IOC の一覧ファイルとログ・現在の接続を照合し、結果を TSV で出力する (checks/ioc.sh が整形する)。

IOC ファイルの書式 (1 行 1 件、# 以降はコメントとして結果に表示する):
  38.244.50[.]120        # 攻撃者のサーバー      -> IP (IPv4 / IPv6)
  xcai[.]pro                                      -> ドメイン (サブドメインも一致)
  hxxp://203.0.113.5:8080/x                       -> URL はホスト部分を IP / ドメインとして扱う
  /.claude/settings.json                          -> パス (Web サーバーへのリクエストと照合)
defang 表記 ([.] (.) [:] hxxp) はそのまま書いてよい。

出力 (TSV):
  IOC   <種類> <値> <出典> <一致した行数> <うち新規> <うち成功応答(パスのみ)> <例>
  CONN  <値> <出典> <ss の行>
  ERR   <メッセージ>
新規 = --state ファイルにまだ記録されていない行。--record を付けたときだけ記録を更新する。
"""
import argparse
import glob
import gzip
import hashlib
import ipaddress
import os
import re
import subprocess
import sys

DEFANG = [("[.]", "."), ("(.)", "."), ("[:]", ":"), ("hxxp", "http"), ("hXXp", "http")]
REQUEST_RE = re.compile(r'"[A-Z]+ (\S+) [^"]*" (\d{3})')


def refang(s):
    for a, b in DEFANG:
        s = s.replace(a, b)
    return s


def classify(value):
    m = re.match(r"^[a-z]+://([^/:\s]+|\[[^\]]+\])", value, re.I)
    if m:
        value = m.group(1).strip("[]")
    if value.startswith("/"):
        return "path", value
    try:
        return "ip", str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}", value):
        return "domain", value.lower()
    return None, value


def load_iocs(patterns):
    iocs, errors = [], []
    for pat in patterns:
        for path in sorted(glob.glob(pat)):
            with open(path, encoding="utf-8") as f:
                for n, raw in enumerate(f, 1):
                    body, _, comment = raw.partition("#")
                    body = refang(body.strip())
                    if not body:
                        continue
                    kind, value = classify(body)
                    if kind is None:
                        errors.append(f"{path}:{n}: IOC として解釈できません: {body}")
                        continue
                    source = os.path.basename(path)
                    if comment.strip():
                        source += f" / {comment.strip()}"
                    iocs.append({"kind": kind, "value": value, "source": source})
    return iocs, errors


def compile_ioc(ioc):
    v = re.escape(ioc["value"])
    if ioc["kind"] == "ip" and ":" in ioc["value"]:
        return re.compile(rf"(?<![0-9A-Fa-f:]){v}(?![0-9A-Fa-f:])", re.I)
    if ioc["kind"] == "ip":
        # 1.2.3.4:443 のようにポートが続く場合も一致させる
        return re.compile(rf"(?<![0-9.]){v}(?![0-9]|\.\d)")
    if ioc["kind"] == "domain":
        return re.compile(rf"(?<![A-Za-z0-9-]){v}(?![A-Za-z0-9-])", re.I)
    return None


def open_log(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, encoding="utf-8", errors="replace")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ioc", action="append", default=[])
    ap.add_argument("--log", action="append", default=[])
    ap.add_argument("--state", default="")
    ap.add_argument("--record", action="store_true")
    ap.add_argument("--connections", action="store_true")
    args = ap.parse_args()

    iocs, errors = load_iocs(args.ioc)
    for e in errors:
        print(f"ERR\t{e}")
    if not iocs:
        return

    seen = set()
    if args.state and os.path.exists(args.state):
        with open(args.state) as f:
            seen = {line.strip() for line in f}

    for ioc in iocs:
        ioc.update(regex=compile_ioc(ioc), hits=0, new=0, success=0, sample="", new_keys=[])

    logs = sorted({p for pat in args.log for p in glob.glob(pat) if os.path.isfile(p)})
    for path in logs:
        try:
            with open_log(path) as f:
                for line in f:
                    req = None
                    for ioc in iocs:
                        if ioc["kind"] == "path":
                            if ioc["value"] not in line:
                                continue
                            req = req or REQUEST_RE.search(line)
                            if not req or ioc["value"] not in req.group(1):
                                continue
                        elif not ioc["regex"].search(line):
                            continue
                        ioc["hits"] += 1
                        key = hashlib.sha256(f"{ioc['value']}\0{line}".encode()).hexdigest()[:32]
                        if key not in seen:
                            ioc["new"] += 1
                            ioc["new_keys"].append(key)
                            success = ioc["kind"] == "path" and req.group(2).startswith("2")
                            # 例には、成功応答の行があればそれを優先して出す
                            if success and not ioc["success"]:
                                ioc["sample"] = ""
                            ioc["success"] += success
                            if not ioc["sample"]:
                                ioc["sample"] = f"{os.path.basename(path)}: {line.strip()[:200]}"
        except OSError as e:
            print(f"ERR\t{path}: {e.strerror}")

    for ioc in iocs:
        print("\t".join(["IOC", ioc["kind"], ioc["value"], ioc["source"], str(ioc["hits"]),
                         str(ioc["new"]), str(ioc["success"]), ioc["sample"].replace("\t", " ")]))

    if args.connections:
        try:
            ss = subprocess.run(["ss", "-Htunap"], capture_output=True, text=True).stdout
        except OSError:
            ss = ""
            print("ERR\tss を実行できません")
        for line in ss.splitlines():
            for ioc in iocs:
                if ioc["kind"] == "ip" and ioc["regex"].search(line):
                    print("\t".join(["CONN", ioc["value"], ioc["source"], " ".join(line.split())]))

    if args.record and args.state:
        new = [k for ioc in iocs for k in ioc["new_keys"]]
        if new:
            with open(args.state, "a") as f:
                f.write("\n".join(new) + "\n")


if __name__ == "__main__":
    main()
