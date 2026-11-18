# Network Traffic Log Analyzer

A Python tool for a NOC / Junior Network Engineer: parse network traffic logs, store them in a database, summarise them with SQL, detect abnormal traffic, and export an Excel report.

## What it does

- Parses log lines: `TIMESTAMP SRC_IP DST_IP PROTOCOL DST_PORT BYTES ACTION`
- Handles **10,000+ records** (sample log included, or generate a fresh one)
- Stores records in SQLite (`traffic.db`) — `schema.sql` is the same table for **MySQL**
- Summarises with SQL: bandwidth by **protocol**, by **LAN/WAN segment**, and by **hour**
- Detects abnormal traffic:
  - **Repeated failed connections** — one host with 20+ denied attempts (possible scan / brute force)
  - **High request rate** — one host with 200+ requests in a single minute (possible flood)
- Exports `traffic_report.xlsx` with three sheets: By Protocol, Top Talkers, Alerts

## Run it

```bash
pip install -r requirements.txt
python log_analyzer.py --generate   # create a fresh 10,000+ line sample log
python log_analyzer.py              # analyse sample_traffic.log
python log_analyzer.py my_log.txt   # analyse your own log file
```

Output: summary printed in the terminal, `traffic.db` database, `traffic_report.xlsx` Excel report.

## Sample output

```
Parsed 10470 records from sample_traffic.log
--- Bandwidth by protocol (SQL) ---
  TCP: 7523 packets, 5737802 bytes
  UDP: 2462 packets, 1919833 bytes
  ICMP: 485 packets, 372819 bytes
--- Anomaly alerts ---
  ! Repeated failed connections: 192.168.1.99 had 120 denied attempts ...
  ! High request rate: 192.168.1.77 sent 350 requests in one minute ...
```

## Files

| File | What it is |
| --- | --- |
| `log_analyzer.py` | The whole tool: parse, database, SQL summary, anomaly detection, Excel export |
| `sample_traffic.log` | 10,000+ sample traffic records (generated, includes 2 planted anomalies) |
| `schema.sql` | MySQL schema + the summary queries |
| `requirements.txt` | `openpyxl` for the Excel report |

## Skills used

Python · TCP/IP · Log Analysis · SQL (MySQL / SQLite) · Microsoft Excel · Network Monitoring · Troubleshooting
