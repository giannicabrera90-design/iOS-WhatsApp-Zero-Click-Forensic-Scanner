import argparse
import ipaddress
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

# Apple Core Data epoch starts on 2001-01-01 00:00:00 UTC (978307200 seconds after Unix epoch)
APPLE_EPOCH_OFFSET = 978307200


class WhatsAppZeroClickDetector:
    def __init__(self, backup_path):
        """
        :param backup_path: Path to the extracted iOS Sysdiagnose or unencrypted iTunes/Finder backup directory.
        """
        self.backup_path = Path(backup_path)
        self.crash_files = []
        self.whatsapp_dbs = []
        self.knowledge_dbs = []
        self.network_files = []
        self.lock_intervals = []

        self.report = {
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "target_path": str(self.backup_path),
            "crash_findings": [],
            "sqlite_findings": [],
            "device_lock_events": [],
            "network_iocs": [],
            "correlated_alerts": []
        }

    def _apple_time_to_iso(self, apple_timestamp):
        """Converts Apple Core Data timestamp to UTC ISO 8601 string."""
        if apple_timestamp is None:
            return None
        try:
            unix_ts = float(apple_timestamp) + APPLE_EPOCH_OFFSET
            return datetime.fromtimestamp(unix_ts, tz=timezone.utc).isoformat()
        except (ValueError, TypeError):
            return None

    def _apple_time_to_dt(self, apple_timestamp):
        """Converts Apple Core Data timestamp to a timezone-aware UTC datetime object."""
        if apple_timestamp is None:
            return None
        try:
            unix_ts = float(apple_timestamp) + APPLE_EPOCH_OFFSET
            return datetime.fromtimestamp(unix_ts, tz=timezone.utc)
        except (ValueError, TypeError):
            return None

    def _parse_iso_timestamp(self, ts_str):
        """Parses various iOS timestamp formats into a timezone-aware datetime object."""
        if not ts_str:
            return None
        try:
            cleaned = ts_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(cleaned)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            for fmt in ("%Y-%m-%d %H:%M:%S.%f %z", "%Y-%m-%d %H:%M:%S %z", "%Y-%m-%dT%H:%M:%S%z"):
                try:
                    return datetime.strptime(ts_str, fmt)
                except ValueError:
                    continue
        return None

    def _is_public_ip(self, ip_str):
        """Returns True if the IP address is a valid public (non-private, non-loopback) IP."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return not (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_reserved
            )
        except ValueError:
            return False

    def discover_artifacts(self):
        """
        Walks the backup/sysdiagnose directory to locate:
        - Crash and Jetsam logs (.ips, .crash)
        - WhatsApp SQLite databases (ChatStorage.sqlite)
        - iOS System state databases (knowledgeC.db)
        - Network diagnostic logs (netstat, lsof, symptomsd, networkd)
        """
        print(f"Scanning directory for forensic artifacts: {self.backup_path}")
        if not self.backup_path.exists():
            raise FileNotFoundError(f"Target path does not exist: {self.backup_path}")

        manifest_db = self.backup_path / "Manifest.db"
        hashed_whatsapp = {}
        hashed_knowledge = {}

        if manifest_db.exists():
            print("iTunes/Finder backup detected. Querying Manifest.db for hashed system & app databases...")
            try:
                conn = sqlite3.connect(f"file:{manifest_db}?mode=ro", uri=True)
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT fileID, relativePath FROM Files 
                    WHERE relativePath LIKE '%ChatStorage.sqlite%' OR relativePath LIKE '%knowledgeC.db%'
                """)
                for file_id, rel_path in cursor.fetchall():
                    if "ChatStorage.sqlite" in rel_path:
                        hashed_whatsapp[file_id] = rel_path
                    elif "knowledgeC.db" in rel_path:
                        hashed_knowledge[file_id] = rel_path
                conn.close()
            except sqlite3.Error as e:
                print(f"Warning: Could not read Manifest.db (backup might be encrypted): {e}")

        network_keywords = ("netstat", "lsof", "symptoms", "networkd", "mdnsresponder", "ifconfig", "packets")

        for root, _, files in os.walk(self.backup_path):
            for fname in files:
                full_path = Path(root) / fname
                lower_name = fname.lower()

                if lower_name.endswith((".ips", ".crash", ".synced")) or "jetsamevent" in lower_name:
                    self.crash_files.append(full_path)

                elif lower_name == "chatstorage.sqlite" or fname in hashed_whatsapp:
                    self.whatsapp_dbs.append(full_path)

                elif lower_name == "knowledgec.db" or fname in hashed_knowledge:
                    self.knowledge_dbs.append(full_path)

                elif any(kw in lower_name for kw in network_keywords) and lower_name.endswith((".txt", ".log", ".out", ".diag")):
                    self.network_files.append(full_path)

        print(
            f"Artifacts found -> Crashes: {len(self.crash_files)} | "
            f"WhatsApp DBs: {len(self.whatsapp_dbs)} | "
            f"knowledgeC DBs: {len(self.knowledge_dbs)} | "
            f"Network Logs: {len(self.network_files)}"
        )

    def analyze_system_lock_state(self):
        """
        Queries iOS knowledgeC.db (/device/isLocked stream) to extract exact time intervals
        when the device screen was locked (ZVALUEINTEGER = 1).
        """
        for db_path in self.knowledge_dbs:
            print(f"Analyzing iOS system lock history in: {db_path}")
            try:
                conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
                cursor = conn.cursor()

                cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                tables = {row[0] for row in cursor.fetchall()}

                if "ZOBJECT" in tables:
                    query = """
                        SELECT ZSTARTDATE, ZENDDATE, ZVALUEINTEGER
                        FROM ZOBJECT
                        WHERE ZSTREAMNAME = '/device/isLocked'
                        ORDER BY ZSTARTDATE DESC
                    """
                    cursor.execute(query)
                    for start_ts, end_ts, is_locked in cursor.fetchall():
                        start_dt = self._apple_time_to_dt(start_ts)
                        end_dt = self._apple_time_to_dt(end_ts)
                        if start_dt and end_dt and is_locked == 1:
                            self.lock_intervals.append((start_dt, end_dt))

                    print(f"Loaded {len(self.lock_intervals)} screen-locked intervals from knowledgeC.db.")
                conn.close()
            except sqlite3.Error as e:
                print(f"Could not query knowledgeC.db ({db_path.name}): {e}")

    def _was_device_locked_at(self, target_dt):
        """Checks if a given datetime falls within any known screen-locked interval."""
        if not target_dt or not self.lock_intervals:
            return None
        for start_dt, end_dt in self.lock_intervals:
            if start_dt <= target_dt <= end_dt:
                return True
        return False

    def analyze_crash_logs(self):
        """
        Parses iOS .ips (JSON) and legacy .crash logs, separating true memory corruption
        in background/locked states from routine Jetsam RAM management kills.
        """
        print("Analyzing crash logs for ImageIO/WhatsApp memory corruption vs. Jetsam...")
        target_processes = ("ImageIO", "WhatsApp", "NotificationServiceExtension", "applepushserviced")
        corruption_signals = ("EXC_BAD_ACCESS", "SIGSEGV", "SIGBUS", "KERN_INVALID_ADDRESS", "KERN_PROTECTION_FAILURE")
        background_roles = ("Background", "Daemon", "Extension")

        for log_path in self.crash_files:
            try:
                content = log_path.read_text(encoding="utf-8", errors="ignore")
                lines = content.splitlines()
                if not lines:
                    continue

                if lines[0].strip().startswith("{"):
                    self._parse_structured_ips(log_path, lines, target_processes, corruption_signals, background_roles)
                else:
                    self._parse_legacy_crash(log_path, lines, target_processes, corruption_signals)

            except Exception as e:
                print(f"Error reading {log_path.name}: {e}")

        return self.report["crash_findings"]

    def _parse_structured_ips(self, log_path, lines, target_processes, corruption_signals, background_roles):
        """Parses structured JSON .ips crash reports."""
        try:
            header = json.loads(lines[0])
            body = json.loads("\n".join(lines[1:])) if len(lines) > 1 else {}
        except json.JSONDecodeError:
            return

        proc_name = header.get("procName", "") or body.get("procName", "")
        bug_type = str(header.get("bug_type", ""))
        timestamp = header.get("timestamp") or body.get("captureTime")
        proc_role = body.get("procRole", "Unknown")

        exception_info = body.get("exception", {})
        exc_type = exception_info.get("type", "")
        exc_signal = exception_info.get("signal", "")
        exc_subtype = exception_info.get("subtype", "")
        termination = body.get("termination", {})

        raw_summary = f"{proc_name} | {exc_type} ({exc_signal}) | {exc_subtype} | {termination}"
        is_target = any(tp.lower() in proc_name.lower() for tp in target_processes) or "ImageIO" in content_frames(body)
        if not is_target:
            return

        crash_dt = self._parse_iso_timestamp(timestamp)
        locked_at_crash = self._was_device_locked_at(crash_dt)

        # 1. Isolate Jetsam events (bug_type 298) as informational records
        if bug_type == "298" or "jetsam" in log_path.name.lower() or termination.get("namespace") == "JETSAM":
            self.report["crash_findings"].append({
                "file": log_path.name,
                "timestamp": timestamp,
                "process": proc_name,
                "proc_role": proc_role,
                "device_screen_locked": locked_at_crash,
                "severity": "INFO",
                "category": "Routine Jetsam Memory Termination",
                "background_execution": proc_role in background_roles,
                "details": termination.get("indicator", "Memory pressure termination")
            })
            return

        # 2. Evaluate genuine memory corruption
        has_corruption = any(sig in raw_summary for sig in corruption_signals)
        if has_corruption:
            is_background = proc_role in background_roles or "NotificationService" in proc_name
            zero_click_context = is_background or (locked_at_crash is True)
            severity = "HIGH (Potential Zero-Click Exploit)" if zero_click_context else "MEDIUM (Foreground Memory Crash)"
            self.report["crash_findings"].append({
                "file": log_path.name,
                "timestamp": timestamp,
                "process": proc_name,
                "proc_role": proc_role,
                "device_screen_locked": locked_at_crash,
                "severity": severity,
                "category": "Memory Corruption",
                "background_execution": is_background,
                "details": f"{exc_type} - {exc_signal} ({exc_subtype})"
            })

    def _parse_legacy_crash(self, log_path, lines, target_processes, corruption_signals):
        """Fallback parser for plain-text .crash logs."""
        full_text = "\n".join(lines)
        if not any(tp in full_text for tp in target_processes):
            return
        is_jetsam = "jetsam" in full_text.lower() or "kern_memorystatus" in full_text.lower()
        has_corruption = any(sig in full_text for sig in corruption_signals)
        is_background = "Background" in full_text or "NotificationService" in full_text
        if has_corruption:
            self.report["crash_findings"].append({
                "file": log_path.name,
                "timestamp": None,
                "process": "Legacy Crash Log",
                "proc_role": "Background" if is_background else "Unknown",
                "device_screen_locked": None,
                "severity": "HIGH (Potential Zero-Click Exploit)" if is_background else "MEDIUM",
                "category": "Memory Corruption",
                "background_execution": is_background,
                "details": "Memory corruption signature detected in plain-text crash trace."
            })
        elif is_jetsam:
            self.report["crash_findings"].append({
                "file": log_path.name,
                "timestamp": None,
                "process": "Legacy Jetsam Log",
                "proc_role": "Background",
                "device_screen_locked": None,
                "severity": "INFO",
                "category": "Routine Jetsam Memory Termination",
                "background_execution": True,
                "details": "Routine kern_memorystatus kill."
            })

    def analyze_whatsapp_sqlite(self):
        """
        Inspects WhatsApp's ChatStorage.sqlite for forensic indicators of zero-click delivery.
        """
        high_risk_extensions = (".tiff", ".tif", ".dng", ".webp", ".pdf", ".heic", ".gif")
        for db_path in self.whatsapp_dbs:
            print(f"Analyzing WhatsApp SQLite database: {db_path}")
            try:
                conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
                cursor = conn.cursor()
                cursor.execute("PRAGMA integrity_check;")
                integrity = cursor.fetchone()
                if integrity and integrity[0] != "ok":
                    self.report["sqlite_findings"].append({
                        "database": str(db_path),
                        "severity": "MEDIUM",
                        "issue": f"SQLite integrity check failed: {integrity[0]}"
                    })
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                tables = {row[0] for row in cursor.fetchall()}
                if "ZWAMESSAGE" in tables and "ZWAMEDIAITEM" in tables:
                    query = """
                        SELECT
                            m.Z_PK,
                            m.ZMESSAGEDATE,
                            m.ZFROMJID,
                            m.ZTEXT,
                            m.ZMESSAGETYPE,
                            media.ZMEDIALOCALPATH,
                            media.ZFILESIZE
                        FROM ZWAMESSAGE m
                        LEFT JOIN ZWAMEDIAITEM media ON m.ZMEDIAITEM = media.Z_PK
                        WHERE m.ZISFROMME = 0
                        ORDER BY m.ZMESSAGEDATE DESC
                    """
                    cursor.execute(query)
                    for row in cursor.fetchall():
                        msg_id, msg_date, sender_jid, text, msg_type, local_path, file_size = row
                        iso_date = self._apple_time_to_iso(msg_date)
                        msg_dt = self._apple_time_to_dt(msg_date)
                        locked_when_received = self._was_device_locked_at(msg_dt)
                        local_path_str = (local_path or "").lower()
                        if any(local_path_str.endswith(ext) for ext in high_risk_extensions):
                            self.report["sqlite_findings"].append({
                                "database": db_path.name,
                                "severity": "MEDIUM",
                                "timestamp": iso_date,
                                "device_screen_locked": locked_when_received,
                                "sender": sender_jid,
                                "message_id": msg_id,
                                "issue": "Incoming high-risk ImageIO media format received",
                                "artifact": local_path,
                                "file_size": file_size
                            })
                        if local_path and (file_size is None or file_size == 0):
                            self.report["sqlite_findings"].append({
                                "database": db_path.name,
                                "severity": "HIGH",
                                "timestamp": iso_date,
                                "device_screen_locked": locked_when_received,
                                "sender": sender_jid,
                                "message_id": msg_id,
                                "issue": "Incoming media reference with zero/null file size (possible failed/cleaned payload)",
                                "artifact": local_path
                            })
                conn.close()
            except sqlite3.Error as e:
                self.report["sqlite_findings"].append({
                    "database": str(db_path),
                    "severity": "ERROR",
                    "issue": f"SQLite query error: {e}"
                })
        return self.report["sqlite_findings"]

    def analyze_network_artifacts(self):
        """
        Extracts malicious IP addresses and suspicious domains from Sysdiagnose network logs
        (netstat, lsof, symptomsd, networkd) associated with WhatsApp, ImageIO, or background daemons.
        """
        print("Extracting external IP endpoints and network traces from Sysdiagnose logs...")
        ipv4_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        relevant_procs = ("whatsapp", "nsurlsessiond", "applepushserviced", "assistantd", "networkd", "commcenter")
        seen_endpoints = set()
        for net_file in self.network_files:
            try:
                content = net_file.read_text(encoding="utf-8", errors="ignore")
                for line in content.splitlines():
                    lower_line = line.lower()
                    # Focus on lines mentioning target processes or active ESTABLISHED/SYN_SENT sockets
                    if any(proc in lower_line for proc in relevant_procs) or "established" in lower_line or "syn_sent" in lower_line:
                        found_ips = ipv4_pattern.findall(line)
                        for ip_str in found_ips:
                            if self._is_public_ip(ip_str):
                                proc_tag = next((p for p in relevant_procs if p in lower_line), "system_socket")
                                endpoint_key = (ip_str, proc_tag, net_file.name)
                                if endpoint_key not in seen_endpoints:
                                    seen_endpoints.add(endpoint_key)
                                    self.report["network_iocs"].append({
                                        "source_file": net_file.name,
                                        "associated_process": proc_tag,
                                        "remote_ip": ip_str,
                                        "raw_trace": line.strip()[:220]
                                    })
            except Exception as e:
                print(f"Error parsing network log {net_file.name}: {e}")
        print(f"Extracted {len(self.report['network_iocs'])} external network endpoint indicators.")
        return self.report["network_iocs"]

    def correlate_events(self, time_window_seconds=60):
        """
        Cross-references HIGH/MEDIUM memory corruption crashes with incoming WhatsApp media
        and device lock state within a strict time window (default: 60 seconds).
        """
        print(f"Correlating crash timestamps, screen lock state, and WhatsApp activity (+/- {time_window_seconds}s)...")
        crashes = [c for c in self.report["crash_findings"] if c["category"] == "Memory Corruption" and c.get("timestamp")]
        messages = [m for m in self.report["sqlite_findings"] if m.get("timestamp")]
        for crash in crashes:
            crash_dt = self._parse_iso_timestamp(crash["timestamp"])
            if not crash_dt:
                continue
            for msg in messages:
                msg_dt = self._parse_iso_timestamp(msg["timestamp"])
                if not msg_dt:
                    continue
                delta = abs((crash_dt - msg_dt).total_seconds())
                if delta <= time_window_seconds:
                    is_locked = crash.get("device_screen_locked") is True or msg.get("device_screen_locked") is True
                    self.report["correlated_alerts"].append({
                        "alert_level": "CRITICAL (LOCKED ZERO-CLICK)" if is_locked else "CRITICAL",
                        "time_delta_seconds": round(delta, 2),
                        "device_confirmed_locked": is_locked,
                        "summary": "Memory corruption crash occurred immediately around incoming WhatsApp media delivery.",
                        "crash_event": crash,
                        "whatsapp_event": msg,
                        "suspicious_network_endpoints_count": len(self.report["network_iocs"])
                    })
        return self.report["correlated_alerts"]

    def run_scan(self, output_json=None):
        """Executes the full forensic pipeline and saves a JSON report."""
        self.discover_artifacts()
        self.analyze_system_lock_state()
        self.analyze_crash_logs()
        self.analyze_whatsapp_sqlite()
        self.analyze_network_artifacts()
        self.correlate_events()
        print("\n=== Forensic Scan Summary ===")
        print(f"Total Crash & Jetsam Events Parsed : {len(self.report['crash_findings'])}")
        high_crashes = [c for c in self.report["crash_findings"] if "HIGH" in c["severity"]]
        print(f"High-Risk Background/Locked Crash: {len(high_crashes)}")
        print(f"Suspicious WhatsApp DB Records   : {len(self.report['sqlite_findings'])}")
        print(f"External Network IP Indicators   : {len(self.report['network_iocs'])}")
        print(f"Critical Correlated Alerts       : {len(self.report['correlated_alerts'])}")
        if output_json:
            out_path = Path(output_json)
            out_path.write_text(json.dumps(self.report, indent=4), encoding="utf-8")
            print(f"Full forensic report saved to: {out_path}")
        return self.report


def content_frames(ips_body):
    """Helper to extract framework & binary names from .ips thread stack traces."""
    used_images = ips_body.get("usedImages", [])
    return " ".join(img.get("name", "") for img in used_images if isinstance(img, dict))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Forensic scanner for iOS WhatsApp & ImageIO Zero-Click indicators."
    )
    parser.add_argument(
        "target_path",
        help="Path to the extracted iOS Sysdiagnose directory or unencrypted iTunes backup folder."
    )
    parser.add_argument(
        "-o", "--output",
        default="whatsapp_zeroclick_report.json",
        help="Output path for the JSON forensic report (default: whatsapp_zeroclick_report.json)."
    )
    args = parser.parse_args()
    detector = WhatsAppZeroClickDetector(args.target_path)
    detector.run_scan(output_json=args.output)
