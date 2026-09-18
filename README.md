# bounty-watch

Daily monitor for public bug bounty programs on **HackerOne, Bugcrowd, YesWeHack and Intigriti**.

- **New programs**: alerts you when a program launches. Programs that disappear and come back (suspensions) are tracked separately as **paused / resumed**, so they never show up as new.
- Checks every 6 hours.
- **Scope changes**: tracks assets added to or removed from every program's in-scope and out-of-scope lists.
- **Watchlist infra/code checks** for the programs you pick:
  - new subdomains under wildcard scopes, from crt.sh certificate transparency (passive)
  - frontend deploy and stack changes: new or removed JS bundles, `Server`/`X-Powered-By` changes, generator and title changes, from one GET per in-scope URL
- **Alerts**: a GitHub Issue opens in this repo, which makes GitHub email you. Alerts cover new programs, programs resumed after 3+ days, and every change on your watchlist.
- **Daily scope digest**: one email a day (after 06:00 UTC) listing every asset added to or removed from any **bug bounty** program (VDPs excluded), with its own dashboard page at `scope.html`.
- **Dashboard**: https://abdulsalam-create.github.io/bounty-watch/

Program data comes from [arkadiyt/bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data), which refreshes about every 30 minutes. No logins or scraping.

## Watchlist
Edit `watchlist.json`, or use the ☆ buttons on the dashboard after you save a fine-grained token (this repo only, *Contents: read & write*) under **Settings**. Key formats:

| Platform | Key |
|---|---|
| HackerOne | `h1:<handle>` |
| Bugcrowd | `bc:<slug>` |
| YesWeHack | `ywh:<slug>` |
| Intigriti | `it:<company>/<handle>` |

Changing the watchlist triggers a scan, which records a baseline for new entries.


## Hunt score
Every program gets a 0–100 **hunt score** (see the 🎯 tab) ranking how likely it is to hold fresh, under-hunted attack surface. It is an additive model over signals this tool actually collects:

| Signal | Weight | Why it matters |
|---|---|---|
| Freshness | 34 | days since launch or last scope change (21-day half-life); recent surface is least picked-over |
| New-surface momentum | 24 | scope additions in the last 60 days |
| Attack surface | 18 | wildcards count most, then domains, then single assets |
| Reward | 14 | max bounty, normalized per platform |
| Low saturation | 10 | newer + private programs face less competition |

Unlike a multiplicative score, one weak signal never zeroes a strong target.

## What the watchlist checks detect
For each watchlist program, every 6 hours: frontend **deploys** (new/removed JS bundles, server/stack changes), **new features** (new API endpoints, GraphQL operations and feature flags mined from changed JS), **changelog** updates, **new subdomains** (crt.sh) with a **liveness + subdomain-takeover** check, and **mobile app version** bumps.

## Private programs (optional)
Add repo secrets to include your private invites: `H1_API_USER` + `H1_API_TOKEN` (HackerOne), `INTIGRITI_TOKEN` (Intigriti researcher API). Absent or invalid tokens are ignored and never break the public scan.

## Running
- Automatic: runs every 6 hours (00:17, 06:17, 12:17, 18:17 UTC) through `.github/workflows/scan.yml`.
- Manual: **Actions → daily-scan → Run workflow**, or run `python scan.py` locally (stdlib only).
- The first run only records a baseline. Alerts start from the second run.

## Email
GitHub emails you about new issues in repos you watch, and you watch your own repos by default. Check **Settings → Notifications → Email** on GitHub.
