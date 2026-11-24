# iOS-WhatsApp-Zero-Click-Forensic-Scanner
iOS WhatsApp Zero-Click Forensic Scanner (CVE-2025-55177 &amp; CVE-2025-43300)

A Python-based forensic tool designed to detect zero-click exploitation artifacts and stealthy persistence on Apple devices (iOS, iPadOS, macOS) through differential analysis of “Sysdiagnose,” “.ips” crash logs, system databases (knowledgeC.db), WhatsApp databases (ChatStorage.sqlite), and network traces.

Key Features:
Timeline Correlation of Lock State: Cross-references data with `knowledgeC.db` to determine whether the phone was locked (isLocked = 1) during the crash.
Noise Filters: Isolates routine iOS memory releases (Jetsam) from actual crashes caused by memory corruption (EXC_BAD_ACCESS, SIGSEGV) in critical processes such as “ImageIO” or “WhatsApp”.
Forensic SQLite Audit: Inspects metadata from high-risk messages and attachments targeting buffer overflows.
Network IoC Extraction: Identifies outbound connections to public IPs from system daemons involved in delivering payloads in the background.

Use: First, you need to extract a decompressed Sysdiagnose folder or a decrypted and decompressed Backup. After that, you will need to install the scanner file to use it and execute this command on a external device (preferably a computer):
python scanner.py /path/to/sysdiagnose_or_backup/ -o forensic_report.json

Warning:
This tool is very new, so it may contain errors or inaccuracies, and it will be updated. For a completely precise, accurate, and comprehensive analysis, it is recommended to consult a specialist or use established, specialized forensic tools such as MVT (Mobile Verification Toolkit) from Amnesty Security, or Triangle Check and iShutdown from Kaspersky.
