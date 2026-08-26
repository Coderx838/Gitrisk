"""OSV API client — for optional online vulnerability lookups.

PRIVACY: This module is only used when the user explicitly opts in to online queries.
It NEVER sends repository file paths, source code, or scan results.
It only sends package names and versions — the same data that is in your manifest files.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Optional

OSV_API_BASE = "https://api.osv.dev/v1"


def query_osv_api(ecosystem: str, package: str, version: Optional[str] = None) -> list[dict]:
    """Query the OSV API for vulnerabilities.
    
    PRIVACY: Only sends package name/version to osv.dev (public data).
    Never sends repository contents, file paths, or secrets.
    """
    payload: dict = {
        "package": {
            "name": package,
            "ecosystem": ecosystem,
        }
    }
    if version:
        payload["version"] = version

    url = f"{OSV_API_BASE}/query"
    data = json.dumps(payload).encode()

    try:
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode())
            return result.get("vulns", [])
    except Exception:
        return []