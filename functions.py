import re
from urllib.parse import urlparse
import math

def calculate_entropy(value):
    if not value:
        return 0

    entropy = 0
    for char in set(value):
        probability = value.count(char) / len(value)
        entropy -= probability * math.log2(probability)

    return entropy


def calculate_confidence(variable_name, value):
    score = 50
    suspicious_names = ["api", "key", "token", "secret", "client_secret", "access"]
    fake_words = ["test", "example", "dummy", "placeholder", "changeme", "your_"]

    if any(word in variable_name.lower() for word in suspicious_names):
        score += 20

    if len(value) >= 32:
        score += 15

    if re.search(r"[A-Za-z]", value) and re.search(r"\d", value):
        score += 10

    entropy_value = calculate_entropy(value)
    if entropy_value >= 3.5:
        score += 15
    if entropy_value < 2.5:
        score -= 15

    if any(word in value.lower() for word in fake_words):
        score -= 30

    return max(0, min(score, 100))


def is_internal_url(base_url, url):
    base_domain = urlparse(base_url).netloc
    url_domain = urlparse(url).netloc
    return base_domain == url_domain

ALLOWLIST_WORDS = [
    "example",
    "dummy",
    "test",
    "fake",
    "placeholder",
    "changeme",
    "your_api_key",
    "your-token",
    "localhost"
]
def is_allow_listed(value):
    value = value.lower()
    return any(word in value for word in ALLOWLIST_WORDS)

def is_minified(js_code):
    lines = js_code.splitlines()
    longest_line = 0
    sum_length = 0

    if not lines:
        return False

    for line in lines:
        if len(line) > longest_line:
            longest_line = len(line)
        sum_length += len(line)
    average_line_length = sum_length / len(lines)

    return average_line_length > 300 or longest_line > 1000