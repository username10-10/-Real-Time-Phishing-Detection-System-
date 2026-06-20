# ml/dataset_loader.py
from __future__ import annotations
from pathlib import Path
import pandas as pd

DATA1_PATH = "data/raw/malicious_urls.csv"   # url,type (benign/phishing/malware/defacement...)
DATA2_PATH = "data/raw/phishing_urls.csv"    # url,type (legitimate/phishing)
EXTRA_BENIGN_PATH = "data/raw/extra_benign_urls.txt"

MALICIOUS_TYPES = {"phishing", "malware", "defacement"}

def normalize_url(u: str) -> str:
    u = str(u).strip()
    if not u:
        return ""
    if not u.startswith(("http://", "https://")):
        u = "http://" + u
    return u

def load_data1(path: str = DATA1_PATH) -> pd.DataFrame:
    df = pd.read_csv(path, on_bad_lines="skip")
    df = df[["url", "type"]].dropna()
    df["url"] = df["url"].astype(str).map(normalize_url)
    df["type"] = df["type"].astype(str).str.lower().str.strip()

    # remove corrupted merged rows (common in this dataset)
    df = df[~df["url"].str.contains(r",phishing|,benign|,malware|,defacement", regex=True)]
    df["label"] = df["type"].isin(MALICIOUS_TYPES).astype(int)
    return df[["url", "label"]]

def load_data2(path: str = DATA2_PATH) -> pd.DataFrame:
    df = pd.read_csv(path, on_bad_lines="skip")
    df = df[["url", "type"]].dropna()
    df["url"] = df["url"].astype(str).map(normalize_url)
    df["type"] = df["type"].astype(str).str.lower().str.strip()

    allowed = {"legitimate", "phishing"}
    df = df[df["type"].isin(allowed)]
    df["label"] = (df["type"] == "phishing").astype(int)
    return df[["url", "label"]]

def load_extra_benign(path: str = EXTRA_BENIGN_PATH) -> pd.DataFrame:
    p = Path(path)
    if not p.exists():
        return pd.DataFrame(columns=["url", "label"])

    urls = []
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        u = normalize_url(line.strip())
        if u:
            urls.append(u)

    if not urls:
        return pd.DataFrame(columns=["url", "label"])

    return pd.DataFrame({"url": urls, "label": [0] * len(urls)})

def load_all() -> pd.DataFrame:
    df1 = load_data1()
    df2 = load_data2()
    df3 = load_extra_benign()
    df = pd.concat([df1, df2, df3], ignore_index=True)
    df = df[df["url"].astype(bool)].drop_duplicates(subset=["url"])
    df["label"] = df["label"].astype(int)
    return df
