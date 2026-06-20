import re
import math
from urllib.parse import urlparse
import tldextract

SPECIAL_CHARS_RE = re.compile(r"[@\-_%\?=&]")
IPV4_RE = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b")
IPV6_HINT_RE = re.compile(r":[0-9a-fA-F]{0,4}:")

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly", "cutt.ly", "rebrand.ly"
}

SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "secure", "account", "update", "bank",
    "confirm", "password", "wallet", "payment", "paypal"
]

BRAND_KEYWORDS = ["paypal", "icloud", "microsoft", "apple", "google", "bank"]
SUSPICIOUS_PATH_TOKENS = ["forms", "form", "spreadsheet", "survey", "share", "download", "upload"]
MALWARE_EXTENSIONS = [".exe", ".zip", ".rar", ".scr", ".bat", ".dll"]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    n = len(s)
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def extract_features(url: str) -> dict:
    # ✅ Normalize early (so features are consistent for train + real browsing)
    url = str(url).strip()
    if url and not url.startswith(("http://", "https://")):
        url = "http://" + url

    lower_url = url.lower()
    digit_count = sum(ch.isdigit() for ch in url)

    features = {
        "url_length": len(url),
        "num_dots": url.count("."),
        "has_ip": 1 if IPV4_RE.search(url) else 0,
        "num_subdomains": 0,
        "path_length": 0,
        "has_https": 1 if lower_url.startswith("https://") else 0,
        "num_special_chars": len(SPECIAL_CHARS_RE.findall(url)),
        "tld_length": 0,

        "num_digits": digit_count,
        "digit_ratio": (digit_count / len(url)) if len(url) else 0.0,
        "has_at_symbol": 1 if "@" in url else 0,
        "count_slashes": url.count("/"),
        "has_double_slash_redirect": 1 if url.find("//", url.find("//") + 2) != -1 else 0,

        "nb_hyphens": lower_url.count("-"),
        "nb_underscore": lower_url.count("_"),
        "nb_www": lower_url.count("www"),
        "nb_com": lower_url.count("com"),

        "suspicious_word_count": sum(lower_url.count(w) for w in SUSPICIOUS_WORDS),
        "has_shortener": 0,
        "host_entropy": 0.0,
        "host_length": 0,

        "brand_impersonation": 0,
        "suspicious_path_token_count": 0,
        "has_executable_extension": 0,
    }

    # IPv6 hints
    if IPV6_HINT_RE.search(url) or ("[" in url and "]" in url):
        features["has_ip"] = 1

    # Parse URL
    try:
        parsed = urlparse(url)
    except ValueError:
        return features

    host = (parsed.netloc or "").lower()
    if not host:
        return features

    host_no_port = host.split(":")[0]
    features["host_length"] = len(host_no_port)
    features["has_shortener"] = 1 if host_no_port in SHORTENERS else 0

    ext = tldextract.extract(host_no_port)
    subdomain_part = ext.subdomain
    features["num_subdomains"] = 0 if subdomain_part == "" else len(subdomain_part.split("."))
    features["path_length"] = len(parsed.path or "")
    features["tld_length"] = len(ext.suffix) if ext.suffix else 0
    features["host_entropy"] = _shannon_entropy(host_no_port)

    registrable = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else host_no_port
    for brand in BRAND_KEYWORDS:
        if brand in lower_url and brand not in registrable:
            features["brand_impersonation"] = 1
            break

    path_lower = (parsed.path or "").lower()
    features["suspicious_path_token_count"] = sum(path_lower.count(tok) for tok in SUSPICIOUS_PATH_TOKENS)

    for extn in MALWARE_EXTENSIONS:
        if path_lower.endswith(extn):
            features["has_executable_extension"] = 1
            break

    return features
