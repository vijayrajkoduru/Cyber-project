"""_cloud_helpers — common name permutations + HTTP probes for §6 Cloud Asset Discovery."""
def bucket_candidates(domain):
    base = domain.split(".")[0]  # "example" from "example.com"
    out = []
    suffixes = ["", "-backup", "-backups", "-prod", "-production", "-dev", "-staging",
                "-test", "-assets", "-static", "-uploads", "-media", "-data", "-logs",
                "-archive", "-private", "-public", "-www", "-api", "-cdn"]
    for s in suffixes:
        out.append(f"{base}{s}")
        out.append(f"{s.lstrip('-')}-{base}" if s else None)
    return [b for b in out if b]
