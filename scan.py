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
    fetch_private(progs)
    return progs


def fetch_private(progs):
    """Merge in the user's PRIVATE invited programs (best-effort; needs API tokens as secrets).

    HackerOne: H1_API_USER + H1_API_TOKEN.   Intigriti: INTIGRITI_TOKEN (researcher API).
    Every failure is swallowed so a bad/absent token never breaks the public scan.
    """
    import base64
    u, t = os.environ.get("H1_API_USER"), os.environ.get("H1_API_TOKEN")
    if u and t:
        try:
            auth = base64.b64encode(f"{u}:{t}".encode()).decode()
            hdr = dict(UA, Authorization="Basic " + auth, Accept="application/json")
            page = "https://api.hackerone.com/v1/hackers/programs?page[size]=100"
            n = 0
            while page and n < 10:
                req = urllib.request.Request(page, headers=hdr)
                with urllib.request.urlopen(req, timeout=30, context=CTX) as r:
                    d = json.loads(r.read())
                for row in d.get("data", []):
                    a = row.get("attributes", {})
                    if a.get("state") != "public_mode":  # keep the private ones
                        h = a.get("handle")
                        k = f"h1:{h}"
                        if h and k not in progs:
                            progs[k] = _priv_h1_scope(h, hdr, a)
                page = (d.get("links") or {}).get("next")
                n += 1
            print("[+] merged HackerOne private programs")
        except Exception as e:  # noqa: BLE001
            print(f"[!] H1 private: {e}")
    it = os.environ.get("INTIGRITI_TOKEN")
    if it:
        try:
            hdr = dict(UA, Authorization="Bearer " + it, Accept="application/json")
            req = urllib.request.Request("https://api.intigriti.com/external/researcher/v1/programs", headers=hdr)
            with urllib.request.urlopen(req, timeout=30, context=CTX) as r:
                data = json.loads(r.read())
                for row in (data.get("records", data) if isinstance(data, dict) else data) or []:
                    h = row.get("handle") or row.get("id")
                    comp = row.get("companyHandle", row.get("company", ""))
                    k = f"it:{comp}/{h}" if comp else f"it:{h}"
                    if row.get("confidentialityLevel", row.get("maxConfidentialityLevel")) not in ("Public", 4) and k not in progs:
                        progs[k] = {"name": row.get("name", h), "url": row.get("webLinks", {}).get("detail", ""),
                                    "bounty": 0, "scope": [], "oos": [], "priv": True}
            print("[+] merged Intigriti private programs")
        except Exception as e:  # noqa: BLE001
            print(f"[!] Intigriti private: {e}")


def _priv_h1_scope(handle, hdr, attrs):
    scope = []
    try:
        req = urllib.request.Request(f"https://api.hackerone.com/v1/hackers/programs/{handle}", headers=hdr)
        with urllib.request.urlopen(req, timeout=30, context=CTX) as r:
            for s in json.loads(r.read()).get("relationships", {}).get("structured_scopes", {}).get("data", []):
                a = s.get("attributes", {})
                if a.get("eligible_for_submission") and a.get("asset_identifier"):
                    scope.append(a["asset_identifier"])
    except Exception:  # noqa: BLE001
        pass
    return {"name": attrs.get("name", handle), "url": f"https://hackerone.com/{handle}",
            "bounty": 1 if attrs.get("offers_bounties") else 0, "scope": sorted(set(scope)), "oos": [], "priv": True}


# ---------- watchlist checks ----------

# Shared third-party platforms: an asset hosted here is a repo/app-store/marketplace
# listing, not the program's own site. Fetching them would report the PLATFORM's
# changelog and JS (e.g. github.com's), never the target's, so skip them here.
EXCLUDE_HOSTS = (
    "github.com", "gitlab.com", "bitbucket.org", "sourceforge.net",
    "play.google.com", "apps.apple.com", "itunes.apple.com", "appgallery.huawei.com",
    "chrome.google.com", "microsoftedge.microsoft.com", "addons.mozilla.org",
    "npmjs.com", "pypi.org", "rubygems.org", "hub.docker.com", "packagist.org",
    "apps.shopify.com", "marketplace.atlassian.com", "workspace.google.com",
)


def web_targets(scope):
    urls = []
    for a in scope:
        a = a.strip().split()[0] if a.strip() else ""
        if a.startswith("*."):
            a = a[2:]
        if not re.match(r"^(https?://)?[a-z0-9.-]+\.[a-z]{2,}(/\S*)?$", a, re.I):
            continue
        url = a if a.startswith("http") else "https://" + a
        host = re.sub(r"^https?://", "", url).split("/")[0].lower()
        if any(host == h or host.endswith("." + h) for h in EXCLUDE_HOSTS):
            continue
        urls.append(url)
    return sorted(set(urls))[:MAX_URLS]


def _abs(base, src):
    if src.startswith(("http://", "https://")):
        return src.split("?")[0]
    root = re.match(r"^(https?://[^/]+)", base)
    if src.startswith("/") and root:
        return root.group(1) + src.split("?")[0]
    return base.rsplit("/", 1)[0] + "/" + src.split("?")[0]


def fingerprint(url):
    try:
        body, h = get(url, limit=600_000)
    except Exception as e:  # noqa: BLE001
        return {"err": type(e).__name__}
    html = body.decode("utf-8", "ignore")
    title = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', html, re.I)
    srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)', html, re.I)
    scripts = sorted({s.split("?")[0].rsplit("/", 1)[-1] for s in srcs})
    hl = {k.lower(): v for k, v in h.items()}
    fp = {
        "title": (title.group(1).strip()[:120] if title else ""),
        "server": hl.get("server", ""),
        "powered": hl.get("x-powered-by", ""),
        "gen": gen.group(1) if gen else "",
        "js": scripts[:60],
    }
    fp["hash"] = hashlib.sha1(json.dumps(fp, sort_keys=True).encode()).hexdigest()[:12]
    fp["jsurls"] = sorted({_abs(url, s) for s in srcs})[:40]  # not hashed; used for endpoint extraction
    fp["eps"] = extract_endpoints(html, _host(url))  # endpoints referenced straight from the HTML
    return fp


# Paths / GraphQL ops / feature-flag names pulled from JS and HTML; new ones flag new features.
API_SEG = r"api|v\d|graphql|gql|rest|internal|admin|account|auth|oauth|payment|billing|webhook|checkout|user"
EP_PATH_RE = re.compile(r'["\'`](/(?:' + API_SEG + r')[\w/\-.]{0,60})["\'`]', re.I)
EP_ABS_RE = re.compile(r'\bhttps?://([a-z0-9.-]+\.[a-z]{2,})(/(?:' + API_SEG + r')[\w/\-.]{0,60})', re.I)
GQL_RE = re.compile(r'\b(?:query|mutation)\s+([A-Za-z][A-Za-z0-9_]{3,40})\s*[({]')
FLAG_RE = re.compile(r'["\']((?:feature|flag|ff|enable|beta)[_.-][A-Za-z0-9_.-]{2,40})["\']', re.I)


def _host(url):
    m = re.match(r"https?://([^/]+)", url)
    return m.group(1).lower() if m else ""


def extract_endpoints(text, host=""):
    """Return endpoints qualified with the serving host, e.g. 'app.pinterest.com/v3/pins'."""
    eps = set()
    for p in EP_PATH_RE.findall(text):
        p = p.rstrip("/").lower()
        eps.add(host + p if host else p)  # relative path -> attach the host it was found on
    for h, p in EP_ABS_RE.findall(text):
        eps.add((h + p.rstrip("/")).lower())  # absolute URL already carries its own host
    for m in GQL_RE.findall(text):
        eps.add("gql:" + m)
    for m in FLAG_RE.findall(text):
        eps.add("flag:" + m.lower())
    return sorted(eps)[:400]


def js_endpoints(urls):
    """Download each JS bundle and extract endpoint-like strings, qualified by the bundle's host."""
    found = set()

    def one(u):
        try:
            body, _ = get(u, limit=2_500_000)
            return extract_endpoints(body.decode("utf-8", "ignore"), _host(u))
        except Exception:  # noqa: BLE001
            return []

    with ThreadPoolExecutor(6) as ex:
        for r in ex.map(one, urls[:20]):
            found.update(r)
    return sorted(found)


CHANGELOG_PATHS = ("/changelog", "/releases", "/release-notes", "/whats-new", "/whatsnew",
                   "/docs/changelog", "/product/changelog", "/blog/changelog")
# A real changelog page shows release/version markers; a profile or marketing page does not.
CHANGELOG_SIG = re.compile(r"change\s?log|release notes?|what[’']?s new|v\d+\.\d+\.\d+|version \d+\.\d+|released? (?:on |in |v)?\d", re.I)


def _text(body):
    return re.sub(r"<script.*?</script>|<style.*?</style>|<[^>]+>|\s+", " ",
                  body.decode("utf-8", "ignore"), flags=re.S).strip()


def _similar(a, b):
    """Cheap near-duplicate check: catch-all pages share almost all their word set."""
    wa, wb = set(a.lower().split()), set(b.lower().split())
    if not wa or not wb:
        return False
    return len(wa & wb) / max(len(wa | wb), 1) > 0.85


def changelog_scan(root):
    """Return {path: sha} for pages that are genuinely changelogs.

    Guards against SPA / catch-all hosts (e.g. pinterest.com/<anything> is a profile,
    not a 404) by requiring the page to differ from a known-garbage path AND to carry
    real release/version markers before we ever treat it as a changelog.
    """
    try:
        junk_body, jh = get(root + "/bw-no-such-path-9z7q", limit=200_000)
        junk = _text(junk_body) if "text/html" in jh.get("Content-Type", "text/html") else ""
    except Exception:  # noqa: BLE001
        junk = ""  # a proper 404 is the good case
    out = {}
    for p in CHANGELOG_PATHS:
        try:
            body, h = get(root + p, limit=400_000)
            if "text/html" not in h.get("Content-Type", "text/html"):
                continue
            text = _text(body)
            if junk and (text == junk or _similar(text, junk)):
                continue  # catch-all host: this path is not really a changelog
            if len(CHANGELOG_SIG.findall(text)) < 2:
                continue  # no real release/version markers -> not a changelog
            out[p] = hashlib.sha1(text.encode()).hexdigest()[:12]
        except Exception:  # noqa: BLE001
            continue
    return out


# Fingerprints of third-party services that show a takeover-able "no such site" page.
TAKEOVER = {
    "github.io": "There isn't a GitHub Pages site here",
    "herokuapp": "No such app",
    "s3.amazonaws": "NoSuchBucket",
    "cloudfront": "The request could not be satisfied",
    "netlify": "Not Found - Request ID",
    "surge.sh": "project not found",
    "fastly": "Fastly error: unknown domain",
    "zendesk": "Help Center Closed",
    "readthedocs": "Maximum number of failed attempts",
    "unbounce": "The requested URL was not found",
    "wpengine": "The site you were looking for couldn't be found",
}


def liveness(host):
    """Resolve a host and, if it looks parked on a takeover-able service, flag it."""
    import socket
    try:
        socket.setdefaulttimeout(6)
        socket.getaddrinfo(host, 443)
    except Exception:  # noqa: BLE001
        return {"live": False}
    info = {"live": True}
    try:
        body, h = get("https://" + host, limit=120_000, timeout=8)
        txt = body.decode("utf-8", "ignore")
        server = (h.get("Server", "") + " " + h.get("Via", "")).lower()
        for svc, sig in TAKEOVER.items():
            if sig.lower() in txt.lower() or svc in server:
                info["takeover"] = svc
                break
    except Exception:  # noqa: BLE001
        pass
    return info


def app_version(asset):
    """Best-effort current version of an in-scope mobile app (iOS via iTunes API, Android via Play page)."""
    try:
        m = re.search(r"id(\d{6,})", asset)  # Apple numeric id
        bundle = re.search(r"apps\.apple\.com.*?/id\d+|/([a-z0-9.]+\.[a-z0-9.]+)$", asset, re.I)
        if "apple.com" in asset and m:
            body, _ = get(f"https://itunes.apple.com/lookup?id={m.group(1)}", timeout=15)
            r = json.loads(body).get("results") or [{}]
            return f"iOS {r[0].get('version', '?')}"
        pid = re.search(r"id=([a-zA-Z0-9_.]+)", asset) or (re.match(r"^[a-z][\w.]+\.[\w.]+$", asset.strip()) and asset.strip())
        gid = pid.group(1) if hasattr(pid, "group") else pid
        if gid:
            body, _ = get(f"https://play.google.com/store/apps/details?id={gid}&hl=en", limit=800_000, timeout=15)
            v = re.search(r'\[\[\["([\d]+\.[\d.]+)"\]\]', body.decode("utf-8", "ignore"))
            return f"Android {v.group(1)}" if v else None
    except Exception:  # noqa: BLE001
        return None
    return None


def mobile_assets(scope):
    out = []
    for a in scope:
        if re.search(r"apps\.apple\.com|play\.google\.com|^[a-z][\w]+(\.[\w]+){2,}$", a.strip(), re.I):
            out.append(a.strip())
    return out[:15]


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


def wildcard_apexes(scope):
    """Clean apex domains from wildcard scope entries, dropping label suffixes like '*.x.com Web Apps'."""
    out = set()
    for a in scope:
        if not a.startswith("*."):
            continue
        d = a[2:].split("/")[0].split()[0].strip().lower()  # first token, no path, no trailing label
        if re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", d):
            out.add(d)
    return out


def watch_checks(key, prog, fps, events):
    first = key not in fps
    state = fps.setdefault(key, {"fp": {}, "subs": {}, "eps": [], "chlog": {}, "apps": {}})
    state.setdefault("eps", [])
    state.setdefault("chlog", {})
    state.setdefault("apps", {})
    urls = web_targets(prog["scope"])
    with ThreadPoolExecutor(8) as ex:
        results = dict(zip(urls, ex.map(fingerprint, urls)))

    # 1. deploys (frontend build / stack changes) + collect new JS bundles for endpoint mining
    new_bundles = []
    html_eps = set()
    for url, fp in results.items():
        old = state["fp"].get(url)
        if old and not first:
            note = diff_fp(old, fp)
            bundles = sorted(set(fp.get("jsurls", [])) - set(old.get("jsurls", [])))
            if note:
                events.append(ev("deploy", key, prog, f"{url}: {note}", js=bundles[:20]))
            new_bundles += bundles
        elif first:
            new_bundles += fp.get("jsurls", [])
        html_eps.update(fp.get("eps", []))
        if "err" not in fp or not old:
            state["fp"][url] = fp

    # 2. new features / endpoints / changelogs (the "what changed in the code" signal)
    eps = set(html_eps)
    if new_bundles:
        eps.update(js_endpoints(new_bundles))
    seen = set(state["eps"])
    fresh = sorted(e for e in eps if e not in seen)
    if fresh and not first and seen:  # need a prior baseline; skips the flood after a format/endpoint reset
        api = [e for e in fresh if not e.startswith(("flag:", "gql:"))]
        gql = [e[4:] for e in fresh if e.startswith("gql:")]
        flags = [e[5:] for e in fresh if e.startswith("flag:")]
        parts = []
        if api:
            parts.append(f"{len(api)} new endpoint(s): " + ", ".join(api[:12]))
        if gql:
            parts.append(f"{len(gql)} new GraphQL op(s): " + ", ".join(gql[:10]))
        if flags:
            parts.append(f"{len(flags)} new feature flag(s): " + ", ".join(flags[:10]))
        events.append(ev("feature", key, prog, "; ".join(parts), api=api[:60], gql=gql[:40], flags=flags[:40], js=sorted(set(new_bundles))[:20]))
    state["eps"] = sorted(seen | eps)[:1500]

    roots = sorted({re.match(r"^(https?://[^/]+)", u).group(1) for u in urls if re.match(r"^https?://[^/]+", u)})[:6]
    for root in roots:
        cur = changelog_scan(root)
        for path, sha in cur.items():
            old = state["chlog"].get(root + path)
            if old and old != sha and not first:
                events.append(ev("changelog", key, prog, f"changelog updated: {root}{path}"))
            state["chlog"][root + path] = sha

    # 3. new subdomains (crt.sh) + liveness / takeover check on the fresh ones
    for d in sorted(wildcard_apexes(prog["scope"]))[:10]:
        subs = crtsh(d)
        if subs is None:
            continue
        old = state["subs"].get(d)
        if old is not None and not first:
            fresh_subs = sorted(set(subs) - set(old))
            if fresh_subs:
                events.append(ev("subdomain", key, prog, f"{len(fresh_subs)} new under {d}: " + ", ".join(fresh_subs[:15]), subs=fresh_subs[:60]))
                with ThreadPoolExecutor(10) as ex:
                    live = dict(zip(fresh_subs[:40], ex.map(liveness, fresh_subs[:40])))
                takeovers = [h for h, i in live.items() if i.get("takeover")]
                alive = [h for h, i in live.items() if i.get("live")]
                if alive:
                    events.append(ev("live-host", key, prog, f"{len(alive)} of the new subdomains resolve: " + ", ".join(alive[:15]), hosts=alive[:60]))
                for h in takeovers:
                    events.append(ev("takeover", key, prog, f"possible subdomain takeover: {h} → {live[h]['takeover']}"))
        state["subs"][d] = subs
        time.sleep(2)

    # 4. mobile app version bumps (new app build usually means new API surface)
    for a in mobile_assets(prog["scope"]):
        v = app_version(a)
        if not v:
            continue
        old = state["apps"].get(a)
        if old and old != v and not first:
            events.append(ev("appversion", key, prog, f"{a}: {old} -> {v}"))
        state["apps"][a] = v


# ---------- hunt score ----------
# Additive 0-100 model. The edge in bug bounty is FRESH, under-hunted attack surface,
# so recency and momentum of change dominate; static reward/breadth fill the rest.
# Additive (not multiplicative) so one weak signal never zeroes a strong target,
# and every input is something this dataset actually has, with no fabricated SLAs.

HUNT_W = {"fresh": 34, "momentum": 24, "surface": 18, "reward": 14, "unsaturated": 10}


def _decay(days, half):
    return 0.5 ** (days / half) if days is not None and days >= 0 else 0.0


def score_program(k, prog, meta, recent):
    """recent[k] = list of scope-add event dates (last 60d) for this program."""
    m = meta.get(k, {})
    today = NOW.timestamp()

    def age(d):
        try:
            return (today - datetime.fromisoformat(d).replace(tzinfo=timezone.utc).timestamp()) / 86400
        except (TypeError, ValueError, AttributeError):
            return None

    scope = prog.get("scope", [])
    wild = sum(1 for a in scope if "*" in a)
    doms = sum(1 for a in scope if "*" not in a and re.search(r"[a-z]\.[a-z]{2,}", a, re.I))

    # fresh: most recent of launch or scope change; 21-day half-life
    last = max([d for d in (m.get("first"), m.get("upd"), m.get("back")) if d], default=None)
    fresh = _decay(age(last), 21)

    # momentum: number of scope-additions in the last 60 days, log-saturated
    adds = recent.get(k, [])
    momentum = min(1.0, math.log1p(len(adds)) / math.log(8)) if adds else 0.0

    # surface: wildcards open many hosts and are worth the most
    surface = min(1.0, (wild * 3 + doms + max(0, len(scope) - wild - doms) * 0.4) / 25)

    # reward: normalized; H1 public data lacks amounts (bounty==1 → neutral 0.5)
    b = prog.get("bounty", 0)
    reward = 0.5 if b == 1 else min(1.0, math.log1p(b) / math.log(20001)) if b else 0.15

    # unsaturated: newer programs are less picked-over; unknown/old age → low
    a0 = age(m.get("first"))
    unsat = 1.0 if a0 is None and last else _decay(a0, 120) if a0 is not None else 0.3
    if prog.get("priv"):
        unsat = 1.0  # private invites have far less competition

    parts = {"fresh": fresh, "momentum": momentum, "surface": surface, "reward": reward, "unsaturated": unsat}
    total = round(sum(HUNT_W[f] * v for f, v in parts.items()), 1)
    why = []
    if fresh > 0.4:
        why.append(f"changed ~{int(age(last))}d ago" if last else "")
    if adds:
        why.append(f"{len(adds)} scope add(s)/60d")
    if wild:
        why.append(f"{wild} wildcard(s)")
    if prog.get("priv"):
        why.append("private invite")
    if b > 1:
        why.append(f"up to ${b:,}")
    return {"score": total, "parts": {f: round(v, 2) for f, v in parts.items()}, "why": [w for w in why if w]}


def score_all(new, meta, feed):
    recent = {}
    floor = _days_ago(60)
    for e in feed:
        if e["t"] == "scope+" and e["d"] >= floor:
            recent.setdefault(e["k"], []).append(e["d"])
    return {k: score_program(k, p, meta, recent) for k, p in new.items()}


# ---------- main ----------

def ev(kind, key, prog, detail, day=TODAY, **extra):
    return {"d": day, "t": kind, "k": key, "n": prog["name"], "u": prog.get("url", ""), "x": detail, **extra}


def scope_ev(kind, k, prog, label, assets, day):
    more = f" (+{len(assets) - 20} more)" if len(assets) > 20 else ""
    verb = "added" if kind == "scope+" else "removed"
    return ev(kind, k, prog, f"{label} {verb}: " + ", ".join(assets[:20]) + more, day,
              a=assets[:300], f=label, b=prog.get("bounty", 0))


def diff(old, new, meta, day=TODAY):
    """Programs that vanish are 'suspended'; a known program that returns is 'resumed', never 'new'."""
    events = []
    for k in sorted(set(new) - set(old)):
        m = meta.get(k)
        if m is None:
            events.append(ev("new", k, new[k], f"{len(new[k]['scope'])} in-scope assets", day))
        else:
            gap = _gap(m.get("gone"), day)
            events.append(ev("resumed", k, new[k], (f"back after {gap} day(s)" if gap is not None else "back")
                             + f"; paused {m.get('flips', 0)} time(s) so far", day))
    for k in sorted(set(old) - set(new)):
        events.append(ev("suspended", k, old[k], "no longer listed (suspended, paused or closed)", day))
    for k in sorted(set(new) & set(old)):
        for f, label in (("scope", "scope"), ("oos", "out-of-scope")):
            add = sorted(set(new[k][f]) - set(old[k][f]))
            rem = sorted(set(old[k][f]) - set(new[k][f]))
            if add:
                events.append(scope_ev("scope+", k, new[k], label, add, day))
            if rem:
                events.append(scope_ev("scope-", k, new[k], label, rem, day))
    return events


def _gap(d0, d1):
    try:
        return (datetime.fromisoformat(d1) - datetime.fromisoformat(d0)).days
    except (TypeError, ValueError):
        return None


def apply_meta(meta, events, current):
    for e in events:
        m = meta.setdefault(e["k"], {"first": None, "upd": None})
        t = e["t"]
        if t == "new":
            m["first"] = m["first"] or e["d"]
            m["upd"] = max(m["upd"] or "", e["d"])
        elif t == "suspended":
            m.update(gone=e["d"], flips=m.get("flips", 0) + 1, n=e["n"], u=e["u"])
        elif t == "resumed":
            m["back"], m["gap"] = e["d"], _gap(m.get("gone"), e["d"])
            m.pop("gone", None)
        else:
            m["upd"] = max(m["upd"] or "", e["d"])
    for k in current:  # remember every program ever seen so a return is never 'new'
        meta.setdefault(k, {"first": None, "upd": None})


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
        evs = diff(prev, snap, meta, day) if prev is not None else []
        apply_meta(meta, evs, snap)
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
    events = diff(old, new, meta) if old is not None else []

    for k in sorted(watch):
        if k in new:
            print(f"[+] watch checks {k}")
            watch_checks(k, new[k], fps, events)
    for k in list(fps):
        if k not in watch:
            del fps[k]

    apply_meta(meta, events, new)
    feed = events + [e for e in feed if e not in events]
    # newest day first, and within a day the highest-value signals first (new features on top)
    feed.sort(key=lambda e: (e["d"], -PRIORITY.get(e["t"], 0)), reverse=True)
    save(CHANGES, feed)
    hunt = score_all(new, meta, feed)
    slim = {k: {**{f: v for f, v in p.items() if f != "oos"}, **meta.get(k, {}), "hunt": hunt[k]["score"],
                "parts": hunt[k]["parts"], "hy": hunt[k]["why"]} for k, p in new.items()}
    paused = {k: m for k, m in meta.items() if m.get("gone") and m["gone"] >= _days_ago(FEED_DAYS) and k not in new}
    save(PROGS, {"updated": NOW.isoformat(timespec="minutes"), "programs": slim, "paused": paused})
    save(SNAP, new)
    save(META, meta)
    save(FPS, fps, pretty=True)
    write_alert(events, watch, first=old is None)
    write_digest(events)
    write_inscope_digest(events)


# Ranking of change types when the feed is ordered within a day (new features first).
PRIORITY = {"takeover": 9, "feature": 8, "live-host": 7, "subdomain": 6, "new": 5,
            "scope+": 4, "appversion": 4, "changelog": 3, "deploy": 2, "resumed": 2, "scope-": 1, "suspended": 1}


def write_digest(events):
    """Queue scope changes on bounty programs; send one digest per day after DIGEST_HOUR UTC."""
    if os.path.exists(DIGEST):
        os.remove(DIGEST)
    st = load(DIGEST_STATE, {"last": None, "pending": []})
    st["pending"] += [e for e in events if e["t"] in ("scope+", "scope-") and e.get("b")]
    if NOW.hour >= DIGEST_HOUR and st["last"] != TODAY:
        st["last"] = TODAY
        pend, st["pending"] = st["pending"], []
        if pend:
            by = {}
            for e in pend:
                by.setdefault(e["k"], []).append(e)
            md = [f"# Daily scope digest {TODAY}\n",
                  f"{len(pend)} scope change(s) across {len(by)} bug bounty program(s) since the last digest.\n",
                  "Dashboard: https://abdulsalam-create.github.io/bounty-watch/scope.html\n"]
            for k, evs in sorted(by.items(), key=lambda kv: -len(kv[1])):
                e0 = evs[0]
                md.append(f"### {e0['n']} (`{k}`)\n{e0['u']}")
                for e in evs:
                    sign = "➕" if e["t"] == "scope+" else "➖"
                    items = e.get("a") or []
                    shown = ", ".join(f"`{a}`" for a in items[:25]) + (f" (+{len(items) - 25} more)" if len(items) > 25 else "")
                    md.append(f"- {sign} **{e.get('f', 'scope')}** {'added' if e['t'] == 'scope+' else 'removed'}: {shown}")
                md.append("")
            body = "\n".join(md)
            if len(body) > 60000:
                body = body[:60000] + "\n\n…truncated, see the dashboard for the full list."
            with open(DIGEST, "w", encoding="utf-8") as f:
                f.write(body + "\n\ncc @abdulsalam-create")
            with open("digest_title.txt", "w", encoding="utf-8") as f:
                f.write(f"Scope digest {TODAY}: {len(pend)} changes across {len(by)} bounty programs")
            print(f"[!] digest written: {len(pend)} changes")
    save(DIGEST_STATE, st)


INSCOPE_STATE, INSCOPE, INSCOPE_LABEL = "data/inscope_digest.json", "inscope.md", "scope"


def write_inscope_digest(events):
    """Dedicated daily email for programs that gained a NEW IN-SCOPE asset (bounty programs only)."""
    if os.path.exists(INSCOPE):
        os.remove(INSCOPE)
    st = load(INSCOPE_STATE, {"last": None, "pending": []})
    # only in-scope additions (field == 'scope'), not out-of-scope, and only paying programs
    st["pending"] += [e for e in events if e["t"] == "scope+" and e.get("f") == INSCOPE_LABEL and e.get("b")]
    if NOW.hour >= DIGEST_HOUR and st["last"] != TODAY:
        st["last"] = TODAY
        pend, st["pending"] = st["pending"], []
        if pend:
            by = {}
            for e in pend:
                by.setdefault(e["k"], []).append(e)
            md = [f"# New in-scope assets {TODAY}\n",
                  f"{len(by)} bug bounty program(s) added new in-scope targets since the last check.\n",
                  "Dashboard: https://abdulsalam-create.github.io/bounty-watch/#inscope\n"]
            for k, evs in sorted(by.items(), key=lambda kv: -sum(len(e.get("a") or []) for e in kv[1])):
                e0 = evs[0]
                assets = sorted({a for e in evs for a in (e.get("a") or [])})
                md.append(f"### {e0['n']} (`{k}`){'  💰 $' + str(e0['b']) if e0['b'] > 1 else ''}\n{e0['u']}")
                md.append("- new in-scope: " + ", ".join(f"`{a}`" for a in assets[:40])
                          + (f" (+{len(assets) - 40} more)" if len(assets) > 40 else ""))
                md.append("")
            body = "\n".join(md)
            if len(body) > 60000:
                body = body[:60000] + "\n\n…truncated, see the dashboard."
            with open(INSCOPE, "w", encoding="utf-8") as f:
                f.write(body + "\n\ncc @abdulsalam-create")
            with open("inscope_title.txt", "w", encoding="utf-8") as f:
                f.write(f"New in-scope {TODAY}: {len(by)} program(s) added targets")
            print(f"[!] in-scope digest written: {len(by)} programs")
    save(INSCOPE_STATE, st)


def _gap_from(e):
    m = re.search(r"back after (\d+) day", e["x"])
    return int(m.group(1)) if m else None


def _days_ago(n):
    return datetime.fromtimestamp(NOW.timestamp() - n * 86400, timezone.utc).strftime("%Y-%m-%d")


def write_alert(events, watch, first):
    if os.path.exists(ALERT):
        os.remove(ALERT)
    if first:
        print("[i] first run: baseline recorded, no alert")
        return
    newp = [e for e in events if e["t"] == "new"]
    back = [e for e in events if e["t"] == "resumed" and e["k"] not in watch and (_gap_from(e) or 0) >= 3]
    mine = [e for e in events if e["k"] in watch]
    # highest-value watchlist signals, surfaced at the very top of the email
    feats = [e for e in mine if e["t"] in ("feature", "takeover")]
    other_scope = sum(1 for e in events if e["t"].startswith("scope") and e["k"] not in watch)
    if not newp and not mine and not back:
        print("[i] nothing noteworthy")
        return
    line = lambda e: f"- **{e['n']}** (`{e['k']}`) {e['u']}\n  - {e['x']}"
    md = [f"# bounty-watch report {TODAY}\n"]
    if feats:
        md += [f"## 🔥 New features / takeovers ({len(feats)})"]
        for e in feats:
            md.append(line(e))
            if e["t"] == "feature" and e.get("api"):
                md.append("    - new endpoints: " + ", ".join(f"`{a}`" for a in e["api"][:15]))
            if e.get("js"):
                md.append("    - new JS: " + ", ".join(e["js"][:5]))
        md.append("")
    if mine:
        md += [f"## Watchlist changes ({len(mine)})"] + [f"{line(e)} _[{e['t']}]_" for e in mine] + [""]
    if newp:
        md += [f"## New programs ({len(newp)})"] + [line(e) for e in newp] + [""]
    if back:
        md += [f"## Resumed after a pause of 3+ days ({len(back)})"] + [line(e) for e in back] + [""]
    if other_scope:
        md.append(f"_{other_scope} scope changes on non-watchlist programs; see the dashboard._\n")
    md.append("Dashboard: https://abdulsalam-create.github.io/bounty-watch/\n\ncc @abdulsalam-create")
    with open(ALERT, "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    with open("alert_title.txt", "w", encoding="utf-8") as f:
        f.write(f"bounty-watch {TODAY}: {len(newp)} new, {len(back)} resumed, {len(mine)} watchlist changes")
    print(f"[!] alert written: {len(newp)} new, {len(mine)} watchlist")


if __name__ == "__main__":
    main()
