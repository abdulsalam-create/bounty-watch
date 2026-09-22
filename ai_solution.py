```python
def format_bounty_watch_report(data):
    header = f"## bounty-watch {data['date']}"
    changes = data.get("changes", {})
    watchlist = changes.get("Pinterest", [])
    
    report = f"{header}\n\n"
    if watchlist:
        report += "### Watchlist changes ({})\n".format(len(watchlist))
        for change in watchlist:
            report += "- **Pinterest** (`bc:pinterest`) {url}\n".format(url=change.get("url"))
            report += "\n".join([f"- {line}" for line in change.get("lines", [])]) + "\n"
        report += "\n[deploy]\n"
    report += "Dashboard: {dashboard}\n".format(dashboard=data.get("dashboard"))
    return report

data = {
    "date": "2026-09-22",
    "changes": {
        "Pinterest": [
            {
                "url": "https://bugcrowd.com/engagements/pinterest",
                "lines": [
                    "https://pinterest.com: new JS bundles: 11274-a4b960dae1ce946a.js, 1455-8f78f771367f7f98.js, 20559-f9b4602e7379730b.js, 21291-a530b38ebf2bf5c8.js, 22309-dc1158e2a52bf4b6.js, 31901-46efc48ec6ec0fab.js, 35867-48c0fff09f75c9ac.js, 40626-ad2c82711041f345.js; removed JS bundles: 11274-8d2d9fed7dbe84e9.js, 1455-2db4b2199ec3a584.js, 21291-5be4124b6233523f.js, 31901-43b89bbd5eb66a31.js, 35867-52a58153e50022f1.js, 40626-dfa8455dde66aa1f.js, 4459-4debda527897fc54.js, 62384-1630995b49df6961.js"
                ]
            }
        ]
    },
    "dashboard": "https://abdulsalam-create.github.io/bounty-watch/"
}

print(format_bounty_watch_report(data))
```