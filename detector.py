
import csv
from collections import Counter
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "logs" / "auth.log"
REPORT_DIR = BASE_DIR / "reports"
REPORT_FILE = REPORT_DIR / "alerts.txt"

THRESHOLD = 5

def main():
    if not LOG_FILE.exists():
        print(f"Log file not found: {LOG_FILE}")
        return

    REPORT_DIR.mkdir(exist_ok=True)
    failed_ips = Counter()
    failed_users = Counter()

    with LOG_FILE.open(newline="") as file:
        reader = csv.DictReader(file)

        for row in reader:
            if row["status"].strip().upper() == "FAILED":
                ip = row["ip"].strip()
                user = row["user"].strip()
                failed_ips[ip] += 1
                failed_users[(ip, user)] += 1

    alerts = []

    for ip, count in failed_ips.items():
        if count >= THRESHOLD:
            alerts.append(
                f"[HIGH] Possible brute-force activity | "
                f"IP: {ip} | Failed attempts: {count}"
            )

    with REPORT_FILE.open("w") as report:
        report.write("SOC FAILED LOGIN DETECTION REPORT\n")
        report.write("=" * 40 + "\n\n")
        report.write(f"Total failed logins: {sum(failed_ips.values())}\n")
        report.write(f"Unique source IPs: {len(failed_ips)}\n\n")

        report.write("FAILED LOGIN COUNTS BY IP\n")
        for ip, count in failed_ips.most_common():
            report.write(f"{ip}: {count}\n")

        report.write("\nSECURITY ALERTS\n")
        if alerts:
            for alert in alerts:
                report.write(alert + "\n")
        else:
            report.write("No suspicious activity detected.\n")

    print("SOC Log Analysis Complete")
    print(f"Total failed logins: {sum(failed_ips.values())}")
    print(f"Alerts generated: {len(alerts)}")

    for alert in alerts:
        print(alert)

    print(f"\nReport saved to: {REPORT_FILE}")

if __name__ == "__main__":
    main()
