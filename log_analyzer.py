#!/usr/bin/env python3
"""
Network Traffic Log Analyzer — NOC / Junior Network Engineer project
Sachin S — https://github.com/sachinsoftwaredevv-crypto

What it does
------------
1. Reads a traffic log file (one record per line):
   TIMESTAMP SRC_IP DST_IP PROTOCOL DST_PORT BYTES ACTION
   Example: 2026-11-18 10:00:01 192.168.1.10 203.0.113.45 TCP 80 512 ALLOW
2. Parses 10,000+ records and stores them in a database (SQLite by default;
   schema.sql is the same table for MySQL).
3. Summarises traffic with SQL: bandwidth by protocol, by LAN/WAN segment,
   and by time period; top talkers and top destination ports.
4. Detects abnormal traffic:
   - repeated failed / denied connection attempts from one host
   - unusually high request rate from a single host
5. Exports an Excel report (traffic_report.xlsx) for performance review.

Run:
    python log_analyzer.py                 # uses sample_traffic.log
    python log_analyzer.py my_log.txt      # your own log file
    python log_analyzer.py --generate      # create a fresh 10,000-line sample log

No log file? Run with --generate first, or copy sample_traffic.log.
Only dependency for the Excel report: openpyxl (pip install -r requirements.txt).
"""

import argparse
import random
import sqlite3
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

# --- Tunable thresholds: change these to match your own network ----------
FAILED_ATTEMPT_LIMIT = 20   # one host with this many DENY/failed hits = alert
HIGH_RATE_LIMIT = 200       # one host with this many requests in one minute = alert

DB_FILE = "traffic.db"
REPORT_FILE = "traffic_report.xlsx"


def generate_sample_log(path, count=10_000, seed=42):
    """Create a realistic sample log so anyone can run the analyzer."""
    random.seed(seed)
    lan_hosts = [f"192.168.1.{i}" for i in range(2, 60)]
    wan_hosts = [f"203.0.113.{i}" for i in range(2, 120)]
    protocols = ["TCP", "UDP", "ICMP"]
    ports = [80, 443, 53, 22, 3389, 25, 8080]
    start = datetime(2026, 11, 18, 9, 0, 0)
    lines = []
    for i in range(count):
        ts = start + timedelta(seconds=random.randint(0, 3600))
        if random.random() < 0.2:
            # Inbound traffic: WAN host talking to a LAN host
            src = random.choice(wan_hosts)
            dst = random.choice(lan_hosts)
        else:
            # Outbound traffic: LAN host talking to a WAN host
            src = random.choice(lan_hosts)
            dst = random.choice(wan_hosts)
        proto = random.choices(protocols, weights=[70, 25, 5])[0]
        port = random.choice(ports) if proto != "ICMP" else 0
        size = random.randint(64, 1500)
        action = "ALLOW"
        lines.append(f"{ts:%Y-%m-%d %H:%M:%S} {src} {dst} {proto} {port} {size} {action}")
    # Plant two anomalies a NOC engineer must catch:
    # 1. One host hammering the network with denied connections (port scan style)
    bad_host = "192.168.1.99"
    for i in range(120):
        ts = start + timedelta(minutes=30, seconds=i * 2)
        lines.append(f"{ts:%Y-%m-%d %H:%M:%S} {bad_host} 203.0.113.10 TCP 22 64 DENY")
    # 2. One host flooding requests in a single minute
    flood_host = "192.168.1.77"
    for i in range(350):
        ts = start + timedelta(minutes=45, seconds=i % 60)
        lines.append(f"{ts:%Y-%m-%d %H:%M:%S} {flood_host} 203.0.113.20 TCP 80 512 ALLOW")
    lines.sort()
    Path(path).write_text("\n".join(lines) + "\n")
    print(f"Generated {len(lines)} sample records -> {path}")


def parse_log(path):
    """Parse the log file into a list of dicts. Skips bad lines and reports them."""
    records, bad = [], 0
    for line in Path(path).read_text().splitlines():
        parts = line.split()
        if len(parts) != 8:
            bad += 1
            continue
        try:
            ts = datetime.strptime(parts[0] + " " + parts[1], "%Y-%m-%d %H:%M:%S")
            records.append({
                "ts": ts, "src": parts[2], "dst": parts[3],
                "protocol": parts[4], "port": int(parts[5]),
                "bytes": int(parts[6]), "action": parts[7],
            })
        except ValueError:
            bad += 1
    if bad:
        print(f"Warning: skipped {bad} malformed line(s).")
    return records


def save_to_db(records, db_file=DB_FILE):
    """Store records in SQLite. schema.sql has the identical table for MySQL."""
    conn = sqlite3.connect(db_file)
    conn.execute("DROP TABLE IF EXISTS traffic")
    conn.execute(
        """CREATE TABLE traffic (
               ts TEXT, src_ip TEXT, dst_ip TEXT,
               protocol TEXT, dst_port INTEGER,
               bytes INTEGER, action TEXT)"""
    )
    conn.executemany(
        "INSERT INTO traffic VALUES (?, ?, ?, ?, ?, ?, ?)",
        [(r["ts"].isoformat(), r["src"], r["dst"], r["protocol"],
          r["port"], r["bytes"], r["action"]) for r in records],
    )
    conn.commit()
    return conn


def sql_summary(conn):
    """Bandwidth by protocol, by segment (LAN/WAN) and by hour — real SQL."""
    print("\n--- Bandwidth by protocol (SQL) ---")
    for proto, packets, total in conn.execute(
            "SELECT protocol, COUNT(*), SUM(bytes) FROM traffic GROUP BY protocol"):
        print(f"  {proto}: {packets} packets, {total} bytes")
    print("\n--- Traffic by segment (SQL) ---")
    for seg, packets, total in conn.execute(
        """SELECT CASE WHEN src_ip LIKE '192.168.%' THEN 'LAN' ELSE 'WAN' END,
                  COUNT(*), SUM(bytes) FROM traffic GROUP BY 1"""):
        print(f"  {seg}: {packets} packets, {total} bytes")
    print("\n--- Traffic by hour (SQL) ---")
    for hour, packets in conn.execute(
            "SELECT substr(ts, 1, 13), COUNT(*) FROM traffic GROUP BY 1 ORDER BY 1"):
        print(f"  {hour}:00 — {packets} packets")


def detect_anomalies(records):
    """Return a list of alert strings for abnormal traffic patterns."""
    alerts = []
    failed = Counter(r["src"] for r in records if r["action"] in ("DENY", "FAILED"))
    for host, count in failed.items():
        if count >= FAILED_ATTEMPT_LIMIT:
            alerts.append(
                f"Repeated failed connections: {host} had {count} denied attempts "
                f"(limit {FAILED_ATTEMPT_LIMIT}) — possible scan / brute force, check this host.")
    per_minute = Counter((r["src"], r["ts"].strftime("%Y-%m-%d %H:%M")) for r in records)
    for (host, minute), count in per_minute.items():
        if count >= HIGH_RATE_LIMIT:
            alerts.append(
                f"High request rate: {host} sent {count} requests in one minute "
                f"({minute}, limit {HIGH_RATE_LIMIT}) — possible flood / misbehaving app.")
    return alerts


def export_excel(records, alerts, report_file=REPORT_FILE):
    """Write the Excel report: protocol summary, top talkers, alerts."""
    from openpyxl import Workbook
    wb = Workbook()
    ws = wb.active
    ws.title = "By Protocol"
    ws.append(["Protocol", "Packets", "Total Bytes"])
    by_proto = defaultdict(lambda: [0, 0])
    for r in records:
        by_proto[r["protocol"]][0] += 1
        by_proto[r["protocol"]][1] += r["bytes"]
    for proto, (packets, total) in sorted(by_proto.items()):
        ws.append([proto, packets, total])

    ws2 = wb.create_sheet("Top Talkers")
    ws2.append(["Source IP", "Packets", "Total Bytes"])
    talkers = defaultdict(lambda: [0, 0])
    for r in records:
        talkers[r["src"]][0] += 1
        talkers[r["src"]][1] += r["bytes"]
    for host, (packets, total) in sorted(talkers.items(), key=lambda x: -x[1][0])[:10]:
        ws2.append([host, packets, total])

    ws3 = wb.create_sheet("Alerts")
    ws3.append(["Alert"])
    for alert in alerts:
        ws3.append([alert])
    if not alerts:
        ws3.append(["No abnormal traffic detected."])
    wb.save(report_file)
    print(f"\nExcel report saved -> {report_file}")


def main():
    parser = argparse.ArgumentParser(description="Network Traffic Log Analyzer")
    parser.add_argument("logfile", nargs="?", default="sample_traffic.log")
    parser.add_argument("--generate", action="store_true",
                        help="generate a fresh 10,000+ line sample log first")
    args = parser.parse_args()

    if args.generate or not Path(args.logfile).exists():
        generate_sample_log(args.logfile)

    records = parse_log(args.logfile)
    if not records:
        print("No valid records found. Check the log file format.")
        sys.exit(1)
    print(f"Parsed {len(records)} records from {args.logfile}")

    conn = save_to_db(records)
    sql_summary(conn)
    conn.close()

    print("\n--- Top destination ports ---")
    for port, count in Counter(r["port"] for r in records).most_common(5):
        print(f"  Port {port}: {count} packets")

    alerts = detect_anomalies(records)
    print("\n--- Anomaly alerts ---")
    if alerts:
        for alert in alerts:
            print("  ! " + alert)
    else:
        print("  No abnormal traffic detected.")
    export_excel(records, alerts)
    print(f"\nDone. Database: {DB_FILE} | Report: {REPORT_FILE}")


if __name__ == "__main__":
    main()
