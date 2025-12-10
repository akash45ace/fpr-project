import json
import csv
import re

# ---------------------------
# ---------------------------

def load_logs(path):
    """Load logs from JSON or CSV file."""
    if path.endswith(".json"):
        with open(path, "r") as f:
            return json.load(f)

    elif path.endswith(".csv"):
        rows = []
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for r in reader:
                rows.append(r)
        return rows
    
    else:
        raise ValueError("Unsupported file format. Use JSON or CSV.")


# ---------------------------
# False Positive (FP) Rules
# ---------------------------

BENIGN_IPS = {
    "10.0.0.1",
    "192.168.1.10",
    "10.0.0.100",     # vulnerability scanner
}

BENIGN_PROCESSES = {
    "chrome.exe",
    "teams.exe",
    "svchost.exe",
    "systemd",
    "osqueryd",
    "wuauclt.exe",     # windows update
}

BENIGN_DOMAINS = {
    "windowsupdate.com",
    "amazonaws.com",
    "microsoft.com"
}

def is_internal_ip(ip):
    if re.match(r"^10\.", ip): return True
    if re.match(r"^192\.168\.", ip): return True
    if re.match(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.", ip): return True
    return False


# ---------------------------
# FP Reduction Logic
# ---------------------------

def reduce_false_positives(alerts):
    clean = []
    fps = []

    for alert in alerts:
        ip = alert.get("source_ip", "")
        process = alert.get("process", "").lower()
        domain = alert.get("domain", "").lower()

        # 1. Internal or trusted IP
        if ip in BENIGN_IPS or is_internal_ip(ip):
            alert["fp_reason"] = "benign/internal IP"
            fps.append(alert)
            continue

        # 2. Known safe process
        if process in BENIGN_PROCESSES:
            alert["fp_reason"] = "safe process"
            fps.append(alert)
            continue

        # 3. Known benign domain
        if any(domain.endswith(d) for d in BENIGN_DOMAINS):
            alert["fp_reason"] = "benign domain"
            fps.append(alert)
            continue

        # else → clean alert
        clean.append(alert)

    return clean, fps


# ---------------------------
# Main Entry
# ---------------------------

if __name__ == "__main__":
    PROGRAM_NAME = "False positive reducer (FPR)"
    AUTHOR_NAME = "Akash kumar"
    
    print("-" * 50)
    print(f"Running Project: {PROGRAM_NAME}")
    print(f"Authored by: {AUTHOR_NAME}")
    print("-" * 50)
    #------------------------------------

    logs = load_logs("alerts.json")  # Replace with your input file path

    clean, fp = reduce_false_positives(logs)

    print("Total Alerts:", len(logs))
    print("False Positives Removed:", len(fp))
    print("Clean Alerts:", len(clean))

    with open("clean_alerts.json", "w") as f:
        json.dump(clean, f, indent=4)

    with open("false_positives.json", "w") as f:
        json.dump(fp, f, indent=4)

    print("\nFP reduction complete! Outputs saved.")
