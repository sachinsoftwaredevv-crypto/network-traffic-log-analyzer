-- Network Traffic Log Analyzer — MySQL schema
-- Same table the Python tool creates in SQLite (traffic.db).
-- Run in MySQL:  mysql -u root -p traffic_logs < schema.sql

CREATE DATABASE IF NOT EXISTS traffic_logs;
USE traffic_logs;

CREATE TABLE IF NOT EXISTS traffic (
    id        INT AUTO_INCREMENT PRIMARY KEY,
    ts        DATETIME NOT NULL,
    src_ip    VARCHAR(45) NOT NULL,
    dst_ip    VARCHAR(45) NOT NULL,
    protocol  VARCHAR(10) NOT NULL,
    dst_port  INT NOT NULL,
    bytes     INT NOT NULL,
    action    VARCHAR(10) NOT NULL,
    INDEX idx_src (src_ip),
    INDEX idx_protocol (protocol),
    INDEX idx_ts (ts)
);

-- Summary queries used by the analyzer:
-- Bandwidth by protocol:
--   SELECT protocol, COUNT(*), SUM(bytes) FROM traffic GROUP BY protocol;
-- Bandwidth by LAN/WAN segment:
--   SELECT CASE WHEN src_ip LIKE '192.168.%' THEN 'LAN' ELSE 'WAN' END,
--          COUNT(*), SUM(bytes) FROM traffic GROUP BY 1;
-- Traffic by hour:
--   SELECT DATE_FORMAT(ts, '%Y-%m-%d %H'), COUNT(*) FROM traffic GROUP BY 1;
-- Repeated failed connections (possible scan):
--   SELECT src_ip, COUNT(*) FROM traffic
--   WHERE action IN ('DENY','FAILED') GROUP BY src_ip HAVING COUNT(*) >= 20;
