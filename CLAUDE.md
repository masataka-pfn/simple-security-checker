# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

ssc (simple-security-checker): Bash checks for Ubuntu/Debian servers, run as root via cron, reporting by email through msmtp. All site-specific values (recipients, URLs, ports, services, schedules) come from YAML (`/etc/ssc/config.yaml` merged over `config/defaults.yaml`). Keep this repo free of any real hostnames, addresses or IOCs beyond the public examples — it is meant to be published.

## Layout

- `bin/ssc` — entry point: `check <name>|all`, `run <job>|all [--force] [--dry-run]`, `list`, `init-baseline`, `install-cron [--print]`, `config validate|dump`.
- `lib/config.py` — loads YAML (PyYAML), deep-merges over defaults (mappings merge, lists replace), validates, and emits `CFG_*` shell variables for `eval`. Scalars → `CFG_a_b`, lists → arrays, lists of mappings → parallel arrays `CFG_a_b__<field>` + `CFG_a_b__count`, mapping keys → `CFG_a_b__keys`. Non `[A-Za-z0-9_]` chars in keys become `_`.
- `lib/common.sh` — output helpers (`ok`/`info`/`warn`/`crit`/`ok_always`/`need_root`), `finish`, `load_config`, `cfg_list` (safe array expansion under `set -u`), `code_in` (HTTP code vs patterns like `2xx`).
- `lib/report.sh` — `run_job`: runs a check, decides whether to mail, sends via msmtp.
- `checks/*.sh` — one script per check; each sources `lib/common.sh`, calls `load_config`, and must end with `finish`.
- `lib/ioc_match.py` — single pass over all logs matching every IOC; outputs TSV that `checks/ioc.sh` formats.
- `site/` — git-ignored folder where an operator keeps their own server's config (real recipients, hostnames, IOC lists, a deploy script). Never commit it, never copy its contents into tracked files, and check `git status` shows nothing under `site/` before committing. If it exists, read `site/CLAUDE.md` for that server's notes.

## Contracts

- **Summary line**: every check must end by printing `要対応項目: N 件` or a line starting with `問題なし`. `run_job` parses this; if neither appears (e.g. a check died under `set -e`), the run is reported as `[実行失敗]` and always mailed. External checks can override the patterns with `ok_pattern` / `issues_pattern`.
- **Notify modes**: `calendar` (issues → mail now; otherwise only on `mail.weekly_day`), `change` (mail only when state OK/NG/FAIL differs from `state_dir/state/<job>`; state is only written after a successful send so failed sends retry), `always`. `verbose` defaults to true only for `always`, so heartbeat mails include OK lines.
- **Checks exit 0** regardless of findings; non-zero only for usage/config errors.
- **Root**: checks run as a normal user but skip root-only sections with `need_root`. `state_dir` is 700 root, so a non-root run must report "needs root", never "baseline missing".
- **`all`** is reserved (`ssc run all`, `ssc check all`) and rejected as a job name by validation.

## Key design decisions

**msmtp user**: msmtp rejects a `~/.msmtprc` not owned by the running user. Cron runs as root, so `mail.run_as` makes `run_job` send via `runuser -u <user> -- msmtp -t`.

**SIGPIPE in changelog parsing**: `zcat changelog | awk` raises SIGPIPE when awk exits early; `security_updates.sh` wraps it in `set +o pipefail` / `set -o pipefail` to avoid false failures under `set -euo pipefail`.

**KEV/EPSS severity scoring**: for each package with a pending `-security` upgrade, `apt-get changelog` is parsed for CVE IDs in entries newer than the installed version (`dpkg --compare-versions`). Each CVE is checked against the CISA KEV catalog (cached in `state_dir`, 24h TTL; falls back to `~/.cache/ssc` when `state_dir` isn't writable) and FIRST EPSS (one batched request, not cached). KEV hit → CRIT regardless of EPSS; otherwise EPSS ≥ `epss_threshold` (0.04) → WARN. Missing `curl`/`jq` or failed fetches degrade to info lines.

**Security regression check**: looks for "SECURITY REGRESSION" in the latest `changelog.Debian.gz` entry of `regression_packages` (+ installed `libssl*`). Always CRIT, except the coded CVE-2026-49975 case (nginx without any `http2` directive → OK). For other CVEs only the message varies: wording like "disabled"/"reverted"/"backed out"/"not applied" means the vendor pulled the fix (no mitigation possible); otherwise "needs individual review". Never auto-clears unreviewed CVEs.

**Sensitive-path exposure (attack_surface)**: hosts = nginx `server_name`s + public IPv4; prefixes = first segment of each `location`. Requests use `curl -k --resolve host:{80,443}:127.0.0.1` (hits local nginx regardless of DNS) and `-r 0-65535` (a real static file answers 206 → CRIT, without downloading it whole). A 200 is CRIT only if the body matches a per-file signature (`looks_leaked`); a `text/html` 200 when a random path also returns 200 is a soft-404 and ignored; any other 200 is WARN. Requests carry the UA from `user_agent` so they can be filtered out of access logs. Request count = hosts × 2 schemes × (prefixes + 1) × paths.

**Baseline diffs**: `init-baseline` saves login users, authorized_keys fingerprints, sudo group members + sudoers hashes and ufw allow rules to `state_dir/baseline/`. Additions are CRIT, removals WARN, and they keep alerting until the change is accepted with `ssc init-baseline`.

**IOC matching**: IOC files accept defanged notation; IPv4 matches allow a trailing `:port` but not longer numbers; domains match subdomains; paths match only inside HTTP request lines, with 2xx responses escalating to CRIT. Matched log lines are hashed into `state_dir/ioc_seen` only when run via `ssc run` (`SSC_RECORD_STATE=1`, not on `--dry-run`), so manual `ssc check ioc` never hides new hits.
