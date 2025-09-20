# Redirect_Fox 🦊

Redirect_Fox is a **fast and intelligent Open Redirect vulnerability scanner** written in **Bash**.  
It is designed for **security researchers**, **penetration testers**, and **bug bounty hunters** who need a reliable tool to detect and confirm open redirect issues in web applications.

---

## ✨ Features

-  **Fast scanning** with parallelized requests.  
-  **Strong payload generation** (encoding + bypass variations).  
-  **Conservative detection** – only shows confirmed vulnerabilities.  
-  **Domain-aware exclusions** (ignores common CDN/analytics domains).  
-  **Retries with backoff** to handle unstable networks.  
-  **Execution time tracking** for each scan.  
-  **Clean report output** in terminal and log file.

---

##  Requirements

- `bash` (v4+)  
- `curl`  
- `grep`, `awk`, `sed` (standard GNU tools)  

> Works on Linux, macOS, and WSL.

---

##  Installation

Clone this repository:

```bash
git clone https://github.com/yourusername/Redirect_Fox.git
cd Redirect_Fox
chmod +x Redirect_Fox.sh

 Usage

Run the script with a URL or a list of targets

# Scan a single target
./Redirect_Fox.sh -u "https://target.com/page?redirect="

# Scan from a file of targets
./Redirect_Fox.sh -l urls.txt

# Save results to a log file
./Redirect_Fox.sh -u "https://target.com/page?next=" -o results.log

