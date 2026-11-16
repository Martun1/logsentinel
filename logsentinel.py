#!/usr/bin/env python3
"""
LogSentinel: a mini-SIEM in one file.

Ingest Linux auth logs (sshd/sudo) and Apache/Nginx access logs into SQLite,
then hunt for attacks with detection rules written in plain SQL (rules/*.sql),
mapped to MITRE ATT&CK.

  python3 logsentinel.py ingest samples/auth.log samples/access.log
  python3 logsentinel.py hunt
  python3 logsentinel.py report -o report.html
  python3 logsentinel.py sql "SELECT src_ip, COUNT(*) FROM auth_events GROUP BY 1"

Author: Martin Ivanov (Martun1) | License: MIT
"""
from __future__ import annotations

import argparse
import html
import re
import sqlite3
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

__version__ = "1.0.0"
ROOT = Path(__file__).resolve().parent
DEFAULT_DB = Path("logsentinel.db")


class C:
    R, G, Y, B, M, CY, BD, DM, X = ("\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[95m",
                                    "\033[96m", "\033[1m", "\033[2m", "\033[0m")

    @classmethod
    def off(cls):
        for k in ("R", "G", "Y", "B", "M", "CY", "BD", "DM", "X"):
            setattr(cls, k, "")


SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEV_COLOR = {"CRITICAL": "M", "HIGH": "R", "MEDIUM": "Y", "LOW": "B"}

# --------------------------------------------------------------------------- #
#  Parsers
# --------------------------------------------------------------------------- #
SYSLOG_RX = re.compile(r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2}) (?P<time>[\d:]{8}) (?P<host>\S+) "
                       r"(?P<svc>[\w\-/.]+)(?:\[\d+\])?: (?P<msg>.*)$")
SSH_PATTERNS = [
    ("FAILED", re.compile(r"Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-f]+)")),
    ("ACCEPTED", re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[\d.:a-f]+)")),
    ("INVALID_USER", re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[\d.:a-f]+)")),
]
SUDO_RX = re.compile(r"^\s*(?P<user>\S+) : .*COMMAND=(?P<cmd>.*)$")
ACCESS_RX = re.compile(r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)[^"]*" '
                       r'(?P<status>\d{3}) (?P<bytes>\d+|-)(?: "[^"]*" "(?P<ua>[^"]*)")?')
MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}


def parse_auth_line(line: str, year: int):
    m = SYSLOG_RX.match(line)
    if not m:
        return None
    ts = f"{year}-{MONTHS.get(m['mon'], 1):02d}-{int(m['day']):02d}T{m['time']}"
    msg, svc = m["msg"], m["svc"]
    if svc.startswith("sshd"):
        # "Failed password for invalid user X" should count once, as FAILED
        for event, rx in SSH_PATTERNS:
            mm = rx.search(msg)
            if mm:
                d = mm.groupdict()
                return (ts, m["host"], "sshd", event, d.get("user"), d.get("ip"), d.get("method"), line)
    elif svc == "sudo":
        mm = SUDO_RX.match(msg)
        if mm:
            return (ts, m["host"], "sudo", "SUDO", mm["user"], None, mm["cmd"][:200], line)
    return None


def parse_access_line(line: str):
    m = ACCESS_RX.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m["ts"].split()[0], "%d/%b/%Y:%H:%M:%S").isoformat()
    except ValueError:
        return None
    return (ts, m["ip"], m["method"], m["path"], int(m["status"]),
            0 if m["bytes"] == "-" else int(m["bytes"]), m["ua"] or "", line)


def detect_kind(path: Path) -> str:
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if ACCESS_RX.match(line):
                return "web"
            if SYSLOG_RX.match(line):
                return "auth"
    return "unknown"


# --------------------------------------------------------------------------- #
#  Database
# --------------------------------------------------------------------------- #
def connect(db: Path) -> sqlite3.Connection:
    con = sqlite3.connect(db)
    con.executescript((ROOT / "schema.sql").read_text())
    return con


def ingest(con: sqlite3.Connection, files: list[Path], year: int) -> None:
    for f in files:
        kind = detect_kind(f)
        auth, web, skipped = [], [], 0
        with f.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.rstrip("\n")
                row = parse_auth_line(line, year) if kind == "auth" else parse_access_line(line) if kind == "web" else None
                if row is None:
                    skipped += 1
                elif kind == "auth":
                    auth.append(row)
                else:
                    web.append(row)
        con.executemany("INSERT INTO auth_events(ts,host,service,event,username,src_ip,method,raw) "
                        "VALUES (?,?,?,?,?,?,?,?)", auth)
        con.executemany("INSERT INTO web_requests(ts,src_ip,method,path,status,bytes,user_agent,raw) "
                        "VALUES (?,?,?,?,?,?,?,?)", web)
        con.commit()
        print(f" {C.G}[+]{C.X} {f.name:<22} {C.DM}({kind}){C.X}  {C.BD}{len(auth) + len(web):>6}{C.X} events "
              f"{C.DM}{skipped} lines skipped{C.X}")


# --------------------------------------------------------------------------- #
#  Rules
# --------------------------------------------------------------------------- #
@dataclass
class Rule:
    id: str
    title: str
    severity: str
    mitre: str
    description: str
    sql: str

    @classmethod
    def load(cls, path: Path) -> "Rule":
        text = path.read_text()
        meta = dict(re.findall(r"^--\s*(\w+):\s*(.+)$", text, re.M))
        return cls(path.stem.split("_")[0], meta.get("title", path.stem), meta.get("severity", "LOW").upper(),
                   meta.get("mitre", ""), meta.get("description", ""), text)


def load_rules(directory: Path) -> list[Rule]:
    return [Rule.load(p) for p in sorted(directory.glob("*.sql"))]


def run_rules(con, rules):
    results = []
    for r in rules:
        cur = con.execute(r.sql)
        cols = [d[0] for d in cur.description]
        rows = cur.fetchall()
        results.append((r, cols, rows))
    return sorted(results, key=lambda x: (not x[2], SEV_ORDER.get(x[0].severity, 9)))


def table(cols, rows, max_w=38) -> str:
    rows = [[("" if v is None else str(v))[:max_w] for v in r] for r in rows]
    w = [max(len(c), *(len(r[i]) for r in rows)) for i, c in enumerate(cols)]
    line = "   " + "  ".join(f"{C.BD}{c:<{w[i]}}{C.X}" for i, c in enumerate(cols))
    out = [line, "   " + "  ".join("─" * x for x in w)]
    out += ["   " + "  ".join(f"{v:<{w[i]}}" for i, v in enumerate(r)) for r in rows]
    return "\n".join(out)


def stats(con):
    q = lambda s: con.execute(s).fetchone()[0]
    return {"auth": q("SELECT COUNT(*) FROM auth_events"), "web": q("SELECT COUNT(*) FROM web_requests"),
            "ips": q("SELECT COUNT(*) FROM (SELECT src_ip FROM auth_events UNION SELECT src_ip FROM web_requests)"),
            "first": q("SELECT MIN(ts) FROM (SELECT ts FROM auth_events UNION ALL SELECT ts FROM web_requests)"),
            "last": q("SELECT MAX(ts) FROM (SELECT ts FROM auth_events UNION ALL SELECT ts FROM web_requests)")}


def cmd_hunt(con, rules, show_clean: bool):
    s = stats(con)
    print(f"\n{C.BD}{C.CY}  ◢◤ LogSentinel v{__version__}: threat hunt{C.X}")
    print(f"  {C.DM}{s['auth']} auth events · {s['web']} web requests · {s['ips']} unique IPs · "
          f"{s['first']} → {s['last']}{C.X}\n")
    hits = 0
    for r, cols, rows in run_rules(con, rules):
        sc = getattr(C, SEV_COLOR.get(r.severity, "B"))
        if rows:
            hits += 1
            print(f" {sc}■ {r.severity:<8}{C.X} {C.BD}{r.id} {r.title}{C.X}  {C.DM}[{r.mitre}]{C.X}")
            print(table(cols, rows[:8]))
            if len(rows) > 8:
                print(f"   {C.DM}... and {len(rows) - 8} more{C.X}")
            print()
        elif show_clean:
            print(f" {C.G}✔ clean   {C.X} {r.id} {r.title}")
    print(f" {C.BD}Result:{C.X} {hits}/{len(rules)} rules triggered\n")
    return hits


def cmd_report(con, rules, out: Path):
    s = stats(con)
    res = run_rules(con, rules)
    sev_c = {"CRITICAL": "#a855f7", "HIGH": "#ef4444", "MEDIUM": "#eab308", "LOW": "#3b82f6"}
    top = con.execute("""SELECT src_ip, SUM(n) FROM (
        SELECT src_ip, COUNT(*) n FROM auth_events WHERE event IN ('FAILED','INVALID_USER') GROUP BY src_ip
        UNION ALL SELECT src_ip, COUNT(*) FROM web_requests WHERE status >= 400 GROUP BY src_ip)
        GROUP BY src_ip ORDER BY 2 DESC LIMIT 6""").fetchall()
    mx = max([t[1] for t in top] or [1])
    hours = dict(con.execute("SELECT SUBSTR(ts,12,2), COUNT(*) FROM auth_events WHERE event IN ('FAILED','INVALID_USER') GROUP BY 1").fetchall())
    hmax = max(hours.values() or [1])
    bars = "".join(f"<div class='h' title='{h}:00 – {hours.get(f'{h:02d}', 0)}'><i style='height:"
                   f"{max(2, 100 * hours.get(f'{h:02d}', 0) // hmax)}%'></i><span>{h:02d}</span></div>" for h in range(24))
    offenders = "".join(f"<div class='row'><code>{html.escape(ip)}</code><div class='bar'><i style='width:"
                        f"{100 * n // mx}%'></i></div><b>{n}</b></div>" for ip, n in top)
    counts = {k: sum(1 for r, _, rows in res if rows and r.severity == k) for k in sev_c}
    tiles = "".join(f"<div class='tile' style='border-color:{c}'><b style='color:{c}'>{counts[k]}</b>{k}</div>"
                    for k, c in sev_c.items())
    cards = ""
    for r, cols, rows in res:
        if not rows:
            continue
        th = "".join(f"<th>{html.escape(c)}</th>" for c in cols)
        tr = "".join("<tr>" + "".join(f"<td>{html.escape(str(v) if v is not None else '')[:80]}</td>" for v in row)
                     + "</tr>" for row in rows[:15])
        cards += (f"<div class='card'><div class='hd'><span class='sev' style='background:{sev_c[r.severity]}'>"
                  f"{r.severity}</span><b>{r.id} · {html.escape(r.title)}</b><span class='mitre'>"
                  f"{html.escape(r.mitre)}</span></div><p>{html.escape(r.description)}</p>"
                  f"<table><tr>{th}</tr>{tr}</table></div>")
    out.write_text(f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>LogSentinel report</title>
<style>body{{margin:0;background:#0a0f1c;color:#e2e8f0;font-family:Inter,Segoe UI,system-ui,sans-serif;padding:32px}}
.w{{max-width:1150px;margin:auto}}h1{{margin:0}}.m{{color:#94a3b8}}.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:22px 0}}
.tile{{background:#111827;border-left:4px solid;border-radius:10px;padding:14px;font-size:13px;color:#94a3b8}}.tile b{{display:block;font-size:30px}}
.two{{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px}}.card{{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:18px;margin-bottom:14px}}
.row{{display:grid;grid-template-columns:130px 1fr 50px;gap:10px;align-items:center;margin:7px 0}}.bar{{background:#1f2937;height:10px;border-radius:5px;overflow:hidden}}
.bar i{{display:block;height:100%;background:linear-gradient(90deg,#f97316,#ef4444)}}.hours{{display:flex;gap:3px;height:140px;align-items:flex-end}}
.h{{flex:1;height:100%;display:flex;flex-direction:column;justify-content:flex-end;align-items:center}}.h i{{display:block;width:100%;background:#38bdf8;border-radius:3px 3px 0 0}}
.h span{{font-size:9px;color:#64748b;margin-top:3px}}.hd{{display:flex;gap:10px;align-items:center}}.mitre{{margin-left:auto;font-size:12px;color:#94a3b8}}
.sev{{font-size:11px;font-weight:700;padding:3px 8px;border-radius:6px;color:#fff}}p{{color:#94a3b8;font-size:14px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}th{{text-align:left;color:#94a3b8;border-bottom:1px solid #1f2937;padding:6px}}
td{{padding:6px;border-bottom:1px solid #111c2e;font-family:ui-monospace,Consolas,monospace}}h3{{margin:0 0 10px}}</style></head>
<body><div class="w"><h1>🛰️ LogSentinel: Threat Hunt Report</h1>
<div class="m">{s['auth']} auth events · {s['web']} web requests · {s['ips']} unique IPs · {s['first']} → {s['last']}</div>
<div class="grid">{tiles}</div>
<div class="two"><div class="card"><h3>Top offending IPs</h3>{offenders}</div>
<div class="card"><h3>Failed logins by hour</h3><div class="hours">{bars}</div></div></div>
{cards}<div class="m">Generated {datetime.now():%Y-%m-%d %H:%M} by LogSentinel v{__version__}</div></div></body></html>""",
                   encoding="utf-8")
    print(f" {C.G}[+]{C.X} HTML report written → {out}")


def cmd_sql(con, query: str):
    cur = con.execute(query)
    if cur.description:
        print(table([d[0] for d in cur.description], cur.fetchall(), max_w=60))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="logsentinel", description="Mini-SIEM: SQL-powered log threat hunting")
    ap.add_argument("--db", type=Path, default=DEFAULT_DB, help="SQLite database (default: logsentinel.db)")
    ap.add_argument("--rules", type=Path, default=ROOT / "rules", help="directory with *.sql rules")
    ap.add_argument("--no-color", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("ingest", help="parse log files into the database")
    p.add_argument("files", nargs="+", type=Path)
    p.add_argument("--year", type=int, default=datetime.now().year, help="year for syslog timestamps")
    p.add_argument("--reset", action="store_true", help="clear the database first")
    p = sub.add_parser("hunt", help="run all detection rules")
    p.add_argument("-a", "--all", action="store_true", help="also list rules with no hits")
    p = sub.add_parser("report", help="generate an HTML report")
    p.add_argument("-o", "--output", type=Path, default=Path("report.html"))
    p = sub.add_parser("sql", help="run your own SQL query")
    p.add_argument("query")
    sub.add_parser("rules", help="list loaded rules")
    a = ap.parse_args(argv)
    if a.no_color:
        C.off()

    con = connect(a.db)
    rules = load_rules(a.rules)
    if a.cmd == "ingest":
        if a.reset:
            con.executescript("DELETE FROM auth_events; DELETE FROM web_requests;")
        print(f"\n{C.BD}{C.CY}  ◢◤ LogSentinel v{__version__}: ingest → {a.db}{C.X}")
        ingest(con, a.files, a.year)
        print()
    elif a.cmd == "hunt":
        return 1 if cmd_hunt(con, rules, a.all) else 0
    elif a.cmd == "report":
        cmd_report(con, rules, a.output)
    elif a.cmd == "sql":
        cmd_sql(con, a.query)
    elif a.cmd == "rules":
        for r in rules:
            sc = getattr(C, SEV_COLOR.get(r.severity, "B"))
            print(f" {sc}{r.severity:<8}{C.X} {C.BD}{r.id}{C.X} {r.title:<55} {C.DM}{r.mitre}{C.X}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
