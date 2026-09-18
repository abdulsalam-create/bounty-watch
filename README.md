# bounty-watch

Daily monitor for public bug bounty programs on **HackerOne, Bugcrowd, YesWeHack and Intigriti**.

- **New programs**: alerts you when a program launches. Programs that disappear and come back (suspensions) are tracked separately as **paused / resumed**, so they never show up as new.
- Checks every 6 hours.
- **Scope changes**: tracks assets added to or removed from every program's in-scope and out-of-scope lists.
- **Watchlist infra/code checks** for the programs you pick:
  - new subdomains under wildcard scopes, from crt.sh certificate transparency (passive)
  - frontend deploy and stack changes: new or removed JS bundles, `Server`/`X-Powered-By` changes, generator and title changes, from one GET per in-scope URL
- **Alerts**: a GitHub Issue opens in this repo, which makes GitHub email you.
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

## Running
- Automatic: runs every 6 hours (00:17, 06:17, 12:17, 18:17 UTC) through `.github/workflows/scan.yml`.
- Manual: **Actions → daily-scan → Run workflow**, or run `python scan.py` locally (stdlib only).
- The first run only records a baseline. Alerts start from the second run.

## Email
GitHub emails you about new issues in repos you watch, and you watch your own repos by default. Check **Settings → Notifications → Email** on GitHub.
