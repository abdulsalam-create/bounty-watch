```python
"""bounty-watch: daily diff of public bug bounty programs + watchlist infra checks.

Stdlib only. Run: python scan.py
"""
import hashlib
import json
import math
import os
import re
import ssl
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

SRC = os.environ.get("BW_SRC") or "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/{}_data.json"
PLATFORMS = {"h1": "hackerone", "bc": "bugcrowd", "ywh": "yeswehack", "it": "intigriti"}
SNAP, FPS, WATCH, META = "data/snapshot.json", "data/fingerprints.json", "watchlist.json", "data/meta.json"
PROGS, CHANGES, ALERT = "docs/data/programs.json", "docs/data/changes.json", "alert.md"
DIGEST_STATE, DIGEST, DIGEST_HOUR = "data/digest.json", "digest.md", 6  # daily scope digest after 06:00 UTC
FEED_DAYS, MAX_URLS, TIMEOUT = 90, 25, 10
UA = {"User-Agent": "Mozilla/5.0 (bounty-watch; +https://github.com/abdulsalam-create/bounty-watch)"}
NOW = datetime.now(timezone.utc)
TODAY = NOW.strftime("%Y-%m-%d")
CTX = ssl.create_default_context()


def load(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def save(path, obj, pretty=False):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=1 if pretty else None, separators=None if pretty else (",", ":"), sort_keys=pretty)


def get(url, timeout=TIMEOUT, limit=None):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
        return r.read(limit) if limit else r.read(), dict(r.headers)


# ---------- normalize ----------

def asset(t):
    for k in ("asset_identifier", "target", "endpoint", "uri", "name"):
        if t.get(k):
            return str(t[k]).strip()
    return ""


def money(v):
    if isinstance(v, dict):
        v = v.get("value")
    try:
        return int(float(v or 0))
    except (TypeError, ValueError):
        return 0


def pkey(tag, p):
    if tag == "h1":
        return p.get("handle")
    if tag == "bc":
        return (p.get("url") or "").rstrip("/").split("/")[-1]
    if tag == "ywh":
        return p.get("id") or p.get("slug")
    return p.get("company_handle", "") + "/" + p.get("handle", "") if p.get("handle") else p.get("id")


def purl(tag, p, k):
    if p.get("url"):
        return p["url"]
    if tag == "ywh":
        return "https://yeswehack.com/programs/" + k.split(":", 1)[1]
    return ""


def normalize(tag, rows):
    out = {}
    for p in rows:
        k = pkey(tag, p)
        if not k:
            continue
        k = f"{tag}:{k}"
        t = p.get("targets") or {}
        ins = sorted({asset(x) for x in t.get("in_scope") or []} - {""})
        oos = sorted({asset(x) for x in t.get("out_of_scope") or []} - {""})
        bounty = money(p.get("max_bounty")) or money(p.get("max_payout"))
        if tag == "h1":
            bounty = 1 if p.get("offers_bounties") else 0  # H1 data has no amounts
        out[k] = {"name": p.get("name") or k, "url": purl(tag, p, k), "bounty": bounty, "scope": ins, "oos": oos}
    return out


def fetch_all():
    progs = {}
    for tag, name in PLATFORMS.items():
        for attempt in range(3):
            try:
                src = SRC.format(name)
                if src.startswith("http"):
                    body, _ = get(src, timeout=120)
                else:
                    with open(src, "rb") as f:
                        body = f.read()
                progs.update(normalize(tag, json.loads(body)))
                break
            except Exception as e:  # noqa: BLE001
                print(f"[!] {name} attempt {attempt + 1}: {e}")
                time.sleep(5)
        else:
            raise SystemExit(f"could not fetch {name}; aborting so the snapshot is not corrupted")
    return progs
```
"""bounty-watch: daily diff of public bug bounty programs + watchlist infra checks.

Stdlib only. Run: python scan.py
"""
import hashlib
import json
import math
import os
import re
import ssl
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

SRC = os.environ.get("BW_SRC") or "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/{}_data.json"
PLATFORMS = {"h1": "hackerone", "bc": "bugcrowd", "ywh": "yeswehack", "it": "intigriti"}
SNAP, FPS, WATCH, META = "data/snapshot.json", "data/fingerprints.json", "watchlist.json", "data/meta.json"
PROGS, CHANGES, ALERT = "docs/data/programs.json", "docs/data/changes.json", "alert.md"
DIGEST_STATE, DIGEST, DIGEST_HOUR = "data/digest.json", "digest.md", 6  # daily scope digest after 06:00 UTC
FEED_DAYS, MAX_URLS, TIMEOUT = 90, 25, 10
UA = {"User-Agent": "Mozilla/5.0 (bounty-watch; +https://github.com/abdulsalam-create/bounty-watch)"}
NOW = datetime.now(timezone.utc)
TODAY = NOW.strftime("%Y-%m-%d")
CTX = ssl.create_default_context()


def load(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def save(path, obj, pretty=False):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=1 if pretty else None, separators=None if pretty else (",", ":"), sort_keys=pretty)


def get(url, timeout=TIMEOUT, limit=None):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
        return r.read(limit) if limit else r.read(), dict(r.headers)


# ---------- normalize ----------

def asset(t):
    for k in ("asset_identifier", "target", "endpoint", "uri", "name"):
        if t.get(k):
            return str(t[k]).strip()
    return ""


def money(v):
    if isinstance(v, dict):
        v = v.get("value")
    try:
        return int(float(v or 0))
    except (TypeError, ValueError):
        return 0


def pkey(tag, p):
    if tag == "h1":
        return p.get("handle")
    if tag == "bc":
        return (p.get("url") or "").rstrip("/").split("/")[-1]
    if tag == "ywh":
        return p.get("id") or p.get("slug")
    return p.get("company_handle", "") + "/" + p.get("handle", "") if p.get("handle") else p.get("id")


def purl(tag, p, k):
    if p.get("url"):
        return p["url"]
    if tag == "ywh":
        return "https://yeswehack.com/programs/" + k.split(":", 1)[1]
    return ""


def normalize(tag, rows):
    out = {}
    for p in rows:
        k = pkey(tag, p)
        if not k:
            continue
        k = f"{tag}:{k}"
        t = p.get("targets") or {}
        ins = sorted({asset(x) for x in t.get("in_scope") or []} - {""})
        oos = sorted({asset(x) for x in t.get("out_of_scope") or []} - {""})
        bounty = money(p.get("max_bounty")) or money(p.get("max_payout"))
        if tag == "h1":
            bounty = 1 if p.get("offers_bounties") else 0  # H1 data has no amounts
        out[k] = {"name": p.get("name") or k, "url": purl(tag, p, k), "bounty": bounty, "scope": ins, "oos": oos}
    return out


def fetch_all():
    progs = {}
    for tag, name in PLATFORMS.items():
        for attempt in range(3):
            try:
                src = SRC.format(name)
                if src.startswith("http"):
                    body, _ = get(src, timeout=120)
                else:
                    with open(src, "rb") as f:
                        body = f.read()
                progs.update(normalize(tag, json.loads(body)))
                break
            except Exception as e:  # noqa: BLE001
                print(f"[!] {name} attempt {attempt + 1}: {e}")
                time.sleep(5)
        else:
            raise SystemExit(f"could not fetch {name}; aborting so the snapshot is not corrupted")
    return progs
