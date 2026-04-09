import os
import re
from datetime import datetime

# ── Settings ──────────────────────────────────────────────
LOG_FILE    = "server.log"
KEYWORDS    = ["CRITICAL", "ERROR", "FAILED LOGIN"]
TODAY       = datetime.now().strftime("%Y-%m-%d")
REPORT_FILE = "security_alert_" + TODAY + ".txt"


# ── Step 1: Read the log file line by line ─────────────────
def read_log():
    lines = []
    with open(LOG_FILE, "r") as file:
        for line in file:
            lines.append(line)
    print("Total lines read:", len(lines))
    return lines


# ── Step 2: Filter out INFO noise, keep only alerts ────────
def filter_alerts(lines):
    alerts = []
    for line in lines:
        for keyword in KEYWORDS:
            if keyword in line:
                alerts.append(line)
                break  # don't double-count the same line
    print("Lines filtered out:", len(lines) - len(alerts))
    print("Alert lines found: ", len(alerts))
    return alerts


# ── Step 3: Count how many times each keyword appears ──────
def count_frequencies(alerts):
    counts = {
        "CRITICAL"    : 0,
        "ERROR"       : 0,
        "FAILED LOGIN": 0
    }
    for line in alerts:
        for keyword in counts:
            if keyword in line:
                counts[keyword] += 1
                break
    return counts


# ── Step 4: Write the security alert report to a file ──────
def write_report(alerts, counts):
    with open(REPORT_FILE, "w") as file:

        # Header
        file.write("=" * 50 + "\n")
        file.write("       SECURITY ALERT REPORT\n")
        file.write("=" * 50 + "\n")
        file.write("Date    : " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n")
        file.write("Source  : " + LOG_FILE + "\n")
        file.write("Total alerts: " + str(len(alerts)) + "\n\n")

        # Summary
        file.write("-" * 50 + "\n")
        file.write("ERROR SUMMARY\n")
        file.write("-" * 50 + "\n")
        for keyword in counts:
            count = counts[keyword]
            bar   = "#" * count
            file.write(keyword + " : " + str(count) + "  " + bar + "\n")

        # Flagged lines
        file.write("\n" + "-" * 50 + "\n")
        file.write("FLAGGED LOG LINES\n")
        file.write("-" * 50 + "\n")
        for line in alerts:
            file.write(line)

    print("Report saved to:", REPORT_FILE)


# ── Step 5: Confirm the file was created using os module ───
def check_file():
    size = os.path.getsize(REPORT_FILE)
    print("File size      :", size, "bytes")


# ── Main: Run all steps in order ───────────────────────────
print("=" * 50)
print("  OpsBot - Security Log Analyser")
print("=" * 50)

lines  = read_log()
alerts = filter_alerts(lines)
counts = count_frequencies(alerts)
write_report(alerts, counts)
check_file()

print("\nDone! Open", REPORT_FILE, "to see the results.")
