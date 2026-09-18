"""bounty-watch: daily diff of public bug bounty programs + watchlist infra checks.

Stdlib only. Run: python scan.py
"""
import hashlib
import json
import os
import re
import ssl
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

SRC = os.environ.get("BW_SRC") or "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/{}_data.json"
PLATFORMS = {"h1": "hackerone", "bc": "bugcrowd", "ywh": "yeswehack", "it": "intigriti"}
SNAP, FPS, WATCH, META = "data/snapshot.json", "data/fingerprints.json", "watchlist.json", "data/meta.json"
PROGS, CHANGES, ALERT = "docs/data/programs.json", "docs/data/changes.json", "alert.md"
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


# ---------- watchlist checks ----------

def web_targets(scope):
    urls = []
    for a in scope:
        a = a.strip().split()[0] if a.strip() else ""
        if a.startswith("*."):
            a = a[2:]
        if not re.match(r"^(https?://)?[a-z0-9.-]+\.[a-z]{2,}(/\S*)?$", a, re.I):
            continue
        urls.append(a if a.startswith("http") else "https://" + a)
    return sorted(set(urls))[:MAX_URLS]


def fingerprint(url):
    try:
        body, h = get(url, limit=600_000)
    except Exception as e:  # noqa: BLE001
        return {"err": type(e).__name__}
    html = body.decode("utf-8", "ignore")
    title = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', html, re.I)
    scripts = sorted({s.split("?")[0].rsplit("/", 1)[-1] for s in re.findall(r'<script[^>]+src=["\']([^"\']+)', html, re.I)})
    hl = {k.lower(): v for k, v in h.items()}
    fp = {
        "title": (title.group(1).strip()[:120] if title else ""),
        "server": hl.get("server", ""),
        "powered": hl.get("x-powered-by", ""),
        "gen": gen.group(1) if gen else "",
        "js": scripts[:60],
    }
    fp["hash"] = hashlib.sha1(json.dumps(fp, sort_keys=True).encode()).hexdigest()[:12]
    return fp


def crtsh(domain):
    try:
        body, _ = get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=60)
        names = set()
        for row in json.loads(body):
            for n in row.get("name_value", "").lower().split("\n"):
                n = n.strip().lstrip("*.")
                if n.endswith(domain):
                    names.add(n)
        return sorted(names)
    except Exception as e:  # noqa: BLE001
        print(f"[!] crt.sh {domain}: {e}")
        return None


def diff_fp(old, new):
    if "err" in new or "err" in old:
        return None
    notes = []
    for f in ("title", "server", "powered", "gen"):
        if old.get(f) != new.get(f):
            notes.append(f"{f}: '{old.get(f)}' -> '{new.get(f)}'")
    add = sorted(set(new["js"]) - set(old["js"]))
    rem = sorted(set(old["js"]) - set(new["js"]))
    if add:
        notes.append("new JS bundles: " + ", ".join(add[:8]))
    if rem:
        notes.append("removed JS bundles: " + ", ".join(rem[:8]))
    return "; ".join(notes) or None


def watch_checks(key, prog, fps, events):
    first = key not in fps
    state = fps.setdefault(key, {"fp": {}, "subs": {}})
    urls = web_targets(prog["scope"])
    with ThreadPoolExecutor(8) as ex:
        results = dict(zip(urls, ex.map(fingerprint, urls)))
    for url, fp in results.items():
        old = state["fp"].get(url)
        if old and not first:
            note = diff_fp(old, fp)
            if note:
                events.append(ev("deploy", key, prog, f"{url} — {note}"))
        if "err" not in fp or not old:
            state["fp"][url] = fp
    for d in sorted({a[2:].split("/")[0] for a in prog["scope"] if a.startswith("*.")})[:10]:
        subs = crtsh(d)
        if subs is None:
            continue
        old = state["subs"].get(d)
        if old is not None and not first:
            new = sorted(set(subs) - set(old))
            if new:
                events.append(ev("subdomain", key, prog, f"{len(new)} new under {d}: " + ", ".join(new[:15])))
        state["subs"][d] = subs
        time.sleep(2)


# ---------- main ----------

def ev(kind, key, prog, detail, day=TODAY):
    return {"d": day, "t": kind, "k": key, "n": prog["name"], "u": prog.get("url", ""), "x": detail}


def diff(old, new, day=TODAY):
    events = []
    for k in sorted(set(new) - set(old)):
        events.append(ev("new", k, new[k], f"{len(new[k]['scope'])} in-scope assets", day))
    for k in sorted(set(old) - set(new)):
        events.append(ev("closed", k, old[k], "program no longer listed", day))
    for k in sorted(set(new) & set(old)):
        for f, label in (("scope", "scope"), ("oos", "out-of-scope")):
            add = sorted(set(new[k][f]) - set(old[k][f]))
            rem = sorted(set(old[k][f]) - set(new[k][f]))
            if add:
                events.append(ev("scope+", k, new[k], f"{label} added: " + ", ".join(add[:20]), day))
            if rem:
                events.append(ev("scope-", k, new[k], f"{label} removed: " + ", ".join(rem[:20]), day))
    return events


def apply_meta(meta, events):
    for e in events:
        m = meta.setdefault(e["k"], {"first": None, "upd": None})
        if e["t"] == "new":
            m["first"] = m["first"] or e["d"]
        if e["t"] != "closed":
            m["upd"] = max(m["upd"] or "", e["d"])


def backfill():
    """One-off: rebuild first-seen / last-updated dates from the source repo's git history."""
    api = "https://api.github.com/repos/arkadiyt/bounty-targets-data/commits?per_page=1&until="
    hdr = dict(UA, **({"Authorization": "Bearer " + os.environ["GITHUB_TOKEN"]} if os.environ.get("GITHUB_TOKEN") else {}))
    days = [365, 180, 120, 90, 75, 60, 45, 30, 25, 21] + list(range(18, 0, -1))
    meta, feed, prev = {}, [], None
    for n in days:
        until = datetime.fromtimestamp(NOW.timestamp() - n * 86400, timezone.utc)
        try:
            req = urllib.request.Request(api + until.strftime("%Y-%m-%dT%H:%M:%SZ"), headers=hdr)
            with urllib.request.urlopen(req, timeout=30, context=CTX) as r:
                sha = json.loads(r.read())[0]["sha"]
            snap = {}
            for tag, name in PLATFORMS.items():
                body, _ = get(f"https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/{sha}/data/{name}_data.json", timeout=120)
                snap.update(normalize(tag, json.loads(body)))
        except Exception as e:  # noqa: BLE001
            print(f"[!] backfill {n}d: {e}")
            continue
        day = until.strftime("%Y-%m-%d")
        print(f"[+] backfill {day}: {len(snap)} programs")
        if prev is not None:
            evs = diff(prev, snap, day)
            apply_meta(meta, evs)
            if n <= FEED_DAYS:
                feed = evs + feed
        prev = snap
    return meta, feed, prev


def main():
    watch = set(load(WATCH, []))
    old = load(SNAP, None)
    fps = load(FPS, {})
    meta = load(META, None)
    feed = [e for e in load(CHANGES, []) if e["d"] >= _days_ago(FEED_DAYS)]
    if meta is None:
        meta, bf_feed, bf_last = backfill()
        feed = [e for e in bf_feed if e["d"] >= _days_ago(FEED_DAYS)] + feed
        old = old if old is not None else bf_last
    new = fetch_all()
    print(f"[+] {len(new)} programs")
    events = diff(old, new) if old is not None else []

    for k in sorted(watch):
        if k in new:
            print(f"[+] watch checks {k}")
            watch_checks(k, new[k], fps, events)
    for k in list(fps):
        if k not in watch:
            del fps[k]

    apply_meta(meta, events)
    feed = events + [e for e in feed if e not in events]
    feed.sort(key=lambda e: e["d"], reverse=True)
    save(CHANGES, feed)
    slim = {k: {**{f: v for f, v in p.items() if f != "oos"}, **meta.get(k, {})} for k, p in new.items()}
    save(PROGS, {"updated": NOW.isoformat(timespec="minutes"), "programs": slim})
    save(SNAP, new)
    save(META, meta)
    save(FPS, fps, pretty=True)
    write_alert(events, watch, first=old is None)


def _days_ago(n):
    return datetime.fromtimestamp(NOW.timestamp() - n * 86400, timezone.utc).strftime("%Y-%m-%d")


def write_alert(events, watch, first):
    if os.path.exists(ALERT):
        os.remove(ALERT)
    if first:
        print("[i] first run: baseline recorded, no alert")
        return
    newp = [e for e in events if e["t"] == "new"]
    mine = [e for e in events if e["k"] in watch]
    other_scope = sum(1 for e in events if e["t"].startswith("scope") and e["k"] not in watch)
    if not newp and not mine:
        print("[i] nothing noteworthy")
        return
    line = lambda e: f"- **{e['n']}** (`{e['k']}`) {e['u']}\n  - {e['x']}"
    md = [f"# bounty-watch report {TODAY}\n"]
    if mine:
        md += [f"## Watchlist changes ({len(mine)})"] + [f"{line(e)} _[{e['t']}]_" for e in mine] + [""]
    if newp:
        md += [f"## New programs ({len(newp)})"] + [line(e) for e in newp] + [""]
    if other_scope:
        md.append(f"_{other_scope} scope changes on non-watchlist programs — see the dashboard._\n")
    md.append("Dashboard: https://abdulsalam-create.github.io/bounty-watch/\n\ncc @abdulsalam-create")
    with open(ALERT, "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    with open("alert_title.txt", "w", encoding="utf-8") as f:
        f.write(f"bounty-watch {TODAY}: {len(newp)} new programs, {len(mine)} watchlist changes")
    print(f"[!] alert written: {len(newp)} new, {len(mine)} watchlist")


if __name__ == "__main__":
    main()
