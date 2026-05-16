
---

## ⚡ Quick Commands (typed from anywhere on the VPS)

Run `vlhelp` to see the list any time.

### Health & Monitoring
| Command | What it does |
|---------|--------------|
| `vlhealth` | 5-second health check |
| `vlcheck` | Full morning check — health + backups + disk + users + cron log |
| `vllogs [N]` | Tail backend logs (default 50 lines) |

### Backup Audit
| Command | What it does |
|---------|--------------|
| `vlbackups` | One-line summary across all 3 tiers |
| `vlaudit` | Detailed per-tier breakdown |
| `vlvault` | Latest VAULT manifest + last cron run |
| `vltools` | Tool snapshot count per category |

### Actions
| Command | What it does |
|---------|--------------|
| `vlsync` | Force-run VAULT sync NOW |
| `vlsnap <user>` | Take a manual snapshot for a user |
| `vlrestore <user>` | Restore a user from their latest snapshot |
| `vlrestart` | Rebuild + restart backend |

### User Management
| Command | What it does |
|---------|--------------|
| `vlusers` | List all users + snapshot counts |
| `vlhelp` | Print this cheat sheet |

