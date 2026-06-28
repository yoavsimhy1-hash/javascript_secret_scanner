import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re
import functions
from functions import is_allow_listed, is_minified
import json

base_url = #insert the desired url here
visited_pages = set()
js_set = set()
inline_scripts = []

# secret rules
RULES = [
    {
        "name": "Possible API Key",
        "pattern": r'(?i)(api[_-]?key|apikey|access[_-]?key)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']',
        "type": "generic"
    },
    {
        "name": "Possible Token",
        "pattern": r'(?i)(token|auth[_-]?token|access[_-]?token)\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{16,})["\']',
        "type": "generic"
    },
    {
        "name": "Possible Secret",
        "pattern": r'(?i)(secret|client[_-]?secret)\s*[:=]\s*["\']([^"\']{8,})["\']',
        "type": "generic"
    },
{
        "name": "AWS Access Key ID",
        "pattern": r'\b(AKIA[0-9A-Z]{16})\b',
        "type": "direct"
    },
    {
        "name": "GitHub Personal Access Token",
        "pattern": r'\b(ghp_[A-Za-z0-9]{36})\b',
        "type": "direct"
    },
    {
        "name": "GitHub Fine-Grained Token",
        "pattern": r'\b(github_pat_[A-Za-z0-9_]{80,})\b',
        "type": "direct"
    },
    {
        "name": "Slack Bot Token",
        "pattern": r'\b(xoxb-[A-Za-z0-9\-]{20,})\b',
        "type": "direct"
    },
    {
        "name": "Stripe Secret Key",
        "pattern": r'\b(sk_live_[A-Za-z0-9]{20,})\b',
        "type": "direct"
    },
    {
        "name": "Google API Key",
        "pattern": r'\b(AIza[0-9A-Za-z\-_]{35})\b',
        "type": "direct"
    },
]

# gets a url, depth - int and max depth - int, and returns all the javascripts on the given url.
def crawl(page_url, depth, max_depth):
    if depth > max_depth:
        return

    if page_url in visited_pages:
        return

    visited_pages.add(page_url)
    print(f"Crawling: {page_url}")

    try:
        response = requests.get(page_url, timeout=10)
    except requests.RequestException:
        return

    soup = BeautifulSoup(response.content, "html.parser")
    for script in soup.find_all("script"):
        src = script.get("src")
        if src:
            full_url = urljoin(page_url, src)
            js_set.add(full_url)
        else:
            inline_code = script.get_text(strip=True)
            if inline_code:
                inline_scripts.append({"url": page_url, "code": inline_code })

    for link in soup.find_all("a", href=True):
        href = link["href"]
        full_url = urljoin(page_url, href)
        if functions.is_internal_url(base_url, full_url):
            crawl(full_url, depth + 1, max_depth)

# gets the findings of the scanner and inserts them into a json file
def save_json_report (findings, filename=r"report.json"):
    report = {
        "target": base_url,
        "total_findings": len(findings),
        "findings": findings
    }

    with open(filename, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print(f"[REPORT] Saved JSON report to {filename}")

# gets javascript code and the url, checks for secrets in the js code based on the rules
def scan_js_code(js_code, url):
    for rule in RULES:
        matches = re.finditer(rule["pattern"], js_code)

        for match in matches:
            line_number = js_code[:match.start()].count("\n") + 1
            lines = js_code.splitlines()
            if rule["type"] == "generic":
                variable_name = match.group(1)
                actual_value = match.group(2)
            elif rule["type"] == "direct":
                variable_name = ""
                actual_value = match.group(1)

            key = (rule["name"], actual_value)

            if not is_minified(js_code):
                start = max(line_number - 3, 0)
                end = min(line_number + 2, len(lines))
                match_context = lines[start:end]
                minified = False
            else:
                start = max(match.start() - 80, 0)
                end = min(match.end() + 80, len(js_code))
                match_context = js_code[start:end]
                minified = True

            if not is_allow_listed(actual_value):
                if key not in seen_keys:
                    seen_keys.add(key)
                    confidence_score = functions.calculate_confidence(variable_name, actual_value)
                    findings.append({"type": rule["name"],
                                     "url": url,
                                     "value": actual_value,
                                     "line": line_number,
                                     "context": match_context,
                                     "confidence": confidence_score})
                    print("[FOUND]", rule["name"])
                    print("URL:", url)
                    print("SECRET:", match.group(0))
                    print("The line number of the finding:", line_number)
                    if not minified:
                        for i in range(start, end):
                            print(f"{i + 1} | {lines[i]}")
                    else:
                        print("Context:", match_context)
                    print("Confidence:", confidence_score)
                    print()
    save_json_report(findings)


crawl(base_url, 0, 5)

#going through every js full url, sends a get request and saves the js into response.
seen_keys = set()
findings = []
for url in js_set: #looks for secrets in external javascripts
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        js_code = response.text

        scan_js_code(js_code, url)

    except requests.RequestException:
        print("[ERROR] failed to fetch", url)
        continue


for inline_script in inline_scripts: #looks for secrets in internal scripts
    url = inline_script["url"]
    js_code = inline_script["code"]

    scan_js_code(js_code, url)