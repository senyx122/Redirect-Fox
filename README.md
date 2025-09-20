# Redirect\_Fox 🦊

Redirect\_Fox is a **fast and intelligent Open Redirect vulnerability scanner** written in **Bash**.
It is designed for **security researchers**, **penetration testers**, and **bug bounty hunters** who need a reliable tool to detect and confirm open redirect issues in web applications.

---

## ✨ Features

* **Fast scanning** with parallelized requests.
* **Strong payload generation** (encoding + bypass variations).
* **Conservative detection** – only shows confirmed vulnerabilities.
* **Domain-aware exclusions** (ignores common CDN/analytics domains).
* **Retries with backoff** to handle unstable networks.
* **Execution time tracking** for each scan.
* **Clean report output** in terminal and log file.
* **Exit codes** for automation and CI integration.
* **Configurable concurrency and timeouts.**

---

## Requirements

* `bash` (v4+)
* `curl`
* `grep`, `awk`, `sed`, `tr`, `sort` (standard GNU tools)
* `xargs` (for parallel execution) — optional but recommended

> Works on Linux, macOS, and WSL.

---

## Installation

Clone this repository:

```bash
git clone https://github.com/senyx122/Redirect-Fox.git
cd Redirect-Fox
chmod +x Redirect_Fox.sh
```

Or download single script:

```bash
curl -Lo Redirect_Fox.sh https://raw.githubusercontent.com/senyx122/Redirect_Fox/main/Redirect-Fox.sh
chmod +x Redirect_Fox.sh
```

---

## Usage

Scan a single target:

```bash
./Redirect_Fox.sh -u "https://target.com/page?redirect="
```

Scan targets from a file (`urls.txt`, one URL per line):

```bash
./Redirect_Fox.sh -l urls.txt
```

Save results to a log file:

```bash
./Redirect_Fox.sh -u "https://target.com/page?next=" -o results.log
```

Run with custom concurrency, timeout and verbosity:

```bash
./Redirect_Fox.sh -u "https://example.com/?r=" -c 20 -t 8 -v
```

---

## Command-line Options

```
-u, --url       Single URL to scan (e.g. "https://site.com/path?next=")
-l, --list      File with newline-separated URLs to scan
-o, --output    Output log file (default: redirect_fox.log)
-c, --concur    Concurrency (number of parallel requests, default: 10)
-t, --timeout   Request timeout in seconds (default: 10)
-r, --retries   Number of retries on failure (default: 2)
-b, --backoff   Backoff base seconds (default: 2)
-e, --exclude   Comma-separated domains to exclude (overrides defaults)
-p, --payloads  Use an alternate payloads file
-v, --verbose   Verbose output
-h, --help      Show help and exit
--version       Show version
```

---

## Payloads & Techniques

Redirect\_Fox ships with a curated set of payloads combining:

* Plain absolute URLs (`https://attacker.com/`)
* Encoded forms (`%2F%2Fattacker.com`, `https%3A%2F%2Fattacker.com%2F`)
* Protocol-relative (`//attacker.com`)
* Nested parameters (`https://site.com/?next=https://attacker.com`)
* Bypass forms (`///attacker.com`, `\attacker.com`)
* Fragment-based (`#https://attacker.com`)

You can add custom payloads in a `payloads.txt` file and pass it with `-p`.

---

## How detection works (conservative approach)

1. For each candidate parameter, the script injects payload variations.
2. It follows redirects (up to a configurable number) and examines:

   * Final Location header
   * HTTP status codes (3xx)
   * Response body meta-refresh or JS redirects
3. The scanner confirms an open redirect only if:

   * A `Location` header or final URL clearly points to the external payload domain *or*
   * A meta-refresh / inline JS immediately redirects to an external payload domain
4. Known analytics/CDN domains are excluded by default from being considered vulnerable (configurable via `-e`).

This conservative method reduces false positives — only high-confidence results are reported.

---

## Output & Log format

Terminal output: concise lines per confirmed finding:

```
[CONFIRMED] https://target.com/login?next= -> https://attacker.com/  (payload: //attacker.com)
```

Log file (CSV-like) columns:

```
timestamp,target,parameter,payload,final_url,status_chain,elapsed_seconds
```

Example line:

```
2025-09-21T00:00:00Z,https://target.com/login,next,//attacker.com,https://attacker.com,302->200,0.87
```

Exit codes:

* `0` — scan completed, no confirmed vulnerabilities
* `1` — at least one confirmed vulnerability found
* `2` — usage error / invalid input
* `3` — runtime error (network, permission, etc.)

These codes make it easy to wire into CI or automation.

---

## Examples

Scan a single URL and save JSON-like log:

```bash
./Redirect_Fox.sh -u "https://example.com/?redirect=" -o result.log -v
```

Scan a list, exclude analytics domains, and increase retries:

```bash
./Redirect_Fox.sh -l targets.txt -e "google-analytics.com,aws.amazon.com" -r 4 -b 3 -c 30
```

Run silently in CI (non-verbose) and return exit code for failure handling:

```bash
./Redirect_Fox.sh -l ci_targets.txt -o ci_results.log || exit $?
```

---

## Performance Tips

* Increase `-c` (concurrency) for faster scanning, but be mindful of target rate-limits and ethics.
* Use a small payload set for wide scans; expand payloads when investigating a suspicious target.
* Use `xargs -P` or GNU `parallel` if integrating with other tooling for very large target lists.

---

## Ethics & Legal

Only scan systems you own or have explicit permission to test.
Unauthorized scanning can be illegal and unethical. This tool is provided for defensive security and authorized testing only.

If you find a vulnerability, follow responsible disclosure practices: don’t exploit beyond proof-of-concept, redact sensitive data in public reports, and contact the target’s security/bug bounty program.

---

## Contributing

Contributions are welcome:

* Add payloads to `payloads.txt`
* Improve detection heuristics (keeping conservative defaults)
* Add wrappers for output conversion (JSON, HTML)
* Add unit / integration tests

Please open an issue or pull request. Follow the existing code style and include tests where applicable.

---

## Troubleshooting / FAQ

Q: The script stops on some targets — SSL errors?
A: Use `-k` (if implemented) to skip certificate verification, or update your CA bundle. Prefer adding trusted certs instead of skipping validation in production.

Q: Too many false positives?
A: Enable verbose mode and inspect the `status_chain` in logs. Tune payloads and exclusions.

Q: Can I add custom header (Authorization / Cookie)?
A: Yes — the script accepts an environment variable `RF_HEADERS` (or add support) containing extra curl headers separated by `\n`.

---

## Changelog

**3.0**

* Improved payload generation and encoding variants
* Parallel requests and configurable concurrency
* Domain-aware exclusions
* Execution time tracking and exit codes

**2.1**

* Retry/backoff logic
* Better logging format

**1.0**

* Initial release

---

## License

MIT License — see `LICENSE` file. Use at your own risk.

---

## Acknowledgements

Thanks to the community of bug bounty researchers and maintainers who contributed payload ideas and detection patterns.

---

## Contact / Reporting

For bugs, feature requests, or security reports, open an issue on GitHub: `https://github.com/yourusername/Redirect_Fox/issues` or contact `your-email@example.com`.


.
