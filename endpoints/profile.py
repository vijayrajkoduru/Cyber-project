"""Profile-based scan endpoints.

Pattern: a profile is a YAML list of tool IDs. The profile endpoint
loads the profile, calls each tool in sequence, aggregates results.
This is how Burp Pro / Acunetix expose "scan modes" — quick, full,
compliance, etc.

Customer hits: POST /api/profile/run?profile=quick-scan
"""
import yaml
import datetime
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException

from tools._shared import ScanRequest, verify_scan_quota

router = APIRouter()

PROFILES_DIR = Path(__file__).parent.parent / "profiles"


def _load_profile(name: str) -> dict:
    """Load a profile YAML. Returns None if not found."""
    path = PROFILES_DIR / f"{name}.yaml"
    if not path.exists():
        return None
    with open(path, "r") as f:
        return yaml.safe_load(f)


@router.get("/api/profile/list")
async def list_profiles(user=Depends(verify_scan_quota)):
    """List all defined scan profiles."""
    if not PROFILES_DIR.exists():
        return {"profiles": []}
    profiles = []
    for p in PROFILES_DIR.glob("*.yaml"):
        try:
            data = yaml.safe_load(p.read_text())
            profiles.append({
                "id":    p.stem,
                "name":  data.get("name", p.stem),
                "desc":  data.get("description", ""),
                "tools": len(data.get("tools", [])),
            })
        except Exception:
            continue
    return {"profiles": profiles}


@router.get("/api/profile/{profile_id}")
async def get_profile(profile_id: str, user=Depends(verify_scan_quota)):
    """Return the YAML spec for a specific profile."""
    data = _load_profile(profile_id)
    if data is None:
        raise HTTPException(404, f"Profile '{profile_id}' not found")
    return data


def register(app):
    app.include_router(router)
