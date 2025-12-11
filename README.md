### False Positive Reduction (FPR)

Automated False Positive Reduction (FPR) for cleaner security logs and focused analyst investigation. Leveraging benign process and network indicators to boost signal-to-noise ratio by 80%+.

---

### Getting Started

This Python script is designed to filter out known benign security alerts (False Positives) based on pre-defined lists of trusted IP addresses, processes, and domains, leaving security analysts with a highly-prioritized list of potential True Positives.

#### **Prerequisites**

* Python 3.x

#### **Installation**

Clone the repository to your local machine (replace `akash45ace/fpr-project` with your actual repository path):

```bash
git clone https://github.com/akash45ace/fpr-project.git
cd fpr-project
```

1. Input Data
The script utilizes the load_logs() function to process input from either JSON or CSV files.

Ensure your security alert data contains the following keys/columns for the filtering logic to work:
Key/Column	Data Type	Purpose
source_ip	string	Used to check against Benign/Internal IP lists.
process	  string	Used to check against the list of known Safe Processes.
domain	  string	Used to check against the list of known Benign Domains.

By default, the script looks for an input file named alerts.json.

2. Run the Script
Execute the script from your terminal:

```bash
python fpr.py
```

Output Files:
The script generates a summary output in the console (Total Alerts, False Positives Removed, Clean Alerts) and creates two new files in the current directory:
```bash
Output                 File	    Description
clean_alerts.json	    Contains  all alerts that did not match any False Positive rules (potential True Positives). This is your actionable alert list.
false_positives.json	Contains  all alerts that matched one of the False Positive rules, along with a new field, "fp_reason", explaining why it was filtered.
```
<img width="1234" height="414" alt="fps" src="https://github.com/user-attachments/assets/ba63116d-7184-484e-b24e-fe0b76d16ac7" />

Configuration (FP Rules)
You can customize the False Positive logic by modifying the sets and functions within the fpr.py file:
```bash
Constant /           Function /	Purpose	                 
BENIGN_IPS	        Explicit list of trusted internal or specific external IP addresses (e.g., known vulnerability scanners).	"10.0.0.100"
BENIGN_PROCESSES	  Explicit list of trusted application executables (filtering is case-insensitive).	"svchost.exe"
BENIGN_DOMAINS	    Explicit list of trusted domain suffixes (e.g., cloud providers, update services).	"amazonaws.com"
is_internal_ip(ip)	Function that automatically filters out all standard RFC 1918 private IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x).	N/A
```

//**//
