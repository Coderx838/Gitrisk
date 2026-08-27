"""Local OSV vulnerability database manager.

Privacy guarantee: This module ONLY downloads public vulnerability data from osv.dev.
It NEVER uploads repository contents, package names from the scanned repo,
file paths, secrets, or scan results to any external service.

Internet access is ONLY used when the user explicitly runs `gitrisk db update`.
All other operations are fully local.
"""

from __future__ import annotations

import gzip
import json
import os
import sqlite3
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, DownloadColumn

console = Console()

# Default local DB path
DEFAULT_DB_DIR = Path.home() / ".gitrisk"
DEFAULT_DB_PATH = DEFAULT_DB_DIR / "vuln.db"
METADATA_PATH = DEFAULT_DB_DIR / "db_meta.json"

# OSV download URL (ecosystem-specific archives)
# Each ecosystem archive is a zip of vulnerability JSON files
OSV_ECOSYSTEM_URLS: dict[str, str] = {
    "PyPI": "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip",
    "npm": "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
    "Go": "https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip",
    "RubyGems": "https://osv-vulnerabilities.storage.googleapis.com/RubyGems/all.zip",
    "crates.io": "https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip",
    "Maven": "https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip",
    "NuGet": "https://osv-vulnerabilities.storage.googleapis.com/NuGet/all.zip",
    "GitHub Actions": "https://osv-vulnerabilities.storage.googleapis.com/GitHub%20Actions/all.zip",
}


class DatabaseManager:
    """Manages the local OSV vulnerability database."""

    def __init__(self, db_path: Path = DEFAULT_DB_PATH) -> None:
        self.db_path = db_path
        self.db_dir = db_path.parent

    def is_available(self) -> bool:
        """Return True if the local database exists and has records."""
        return self.db_path.exists() and self.db_path.stat().st_size > 0

    def update(self, ecosystem: Optional[str] = None) -> None:
        """Download and index OSV vulnerability data.
        
        PRIVACY: Only public OSV data is downloaded.
        No repository data is sent to any server.
        """
        self.db_dir.mkdir(parents=True, exist_ok=True)

        ecosystems = (
            [ecosystem] if ecosystem and ecosystem in OSV_ECOSYSTEM_URLS
            else list(OSV_ECOSYSTEM_URLS.keys())
        )

        conn = sqlite3.connect(self.db_path)
        self._init_schema(conn)

        for eco in ecosystems:
            url = OSV_ECOSYSTEM_URLS[eco]
            console.print(f"  Downloading [cyan]{eco}[/] vulnerability data...")
            try:
                self._download_and_index(conn, eco, url)
            except Exception as e:
                console.print(f"  [yellow]⚠ Failed to download {eco}: {e}[/]")

        conn.commit()
        conn.close()

        # Write metadata
        meta = {
            "updated_at": datetime.now().isoformat(),
            "ecosystems": ecosystems,
        }
        METADATA_PATH.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    def query(
        self,
        ecosystem: str,
        package: str,
        version: Optional[str] = None,
    ) -> list[dict]:
        """Query the local DB for vulnerabilities affecting a package/version."""
        if not self.is_available():
            return []

        from packaging.version import Version, InvalidVersion

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT id, summary, details, affected_versions FROM vulns WHERE ecosystem=? AND package=?",
                (ecosystem, package.lower()),
            ).fetchall()

            if not version:
                return [dict(row) for row in rows]

            # Semantic version matching against affected ranges
            affected_results = []
            try:
                cur_v = Version(version)
            except InvalidVersion:
                cur_v = None

            for row in rows:
                aff_str = row["affected_versions"] or ""
                if not aff_str or aff_str == "*":
                    continue

                tokens = [t.strip() for t in aff_str.split(",") if t.strip()]
                
                if cur_v is None:
                    continue

                # Check ranges (introduced, fixed)
                is_vuln = False
                for token in tokens:
                    try:
                        tok_v = Version(token)
                        if tok_v > Version("0"):
                            if cur_v < tok_v:
                                is_vuln = True
                            elif cur_v >= tok_v:
                                is_vuln = False
                                break
                    except InvalidVersion:
                        pass

                if is_vuln:
                    affected_results.append(dict(row))

            return affected_results
        finally:
            conn.close()

    def status(self) -> dict:
        """Return status info about the local database."""
        if not self.is_available():
            return {"exists": False}

        conn = sqlite3.connect(self.db_path)
        count = conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0]
        conn.close()

        meta = {}
        if METADATA_PATH.exists():
            meta = json.loads(METADATA_PATH.read_text(encoding="utf-8"))

        return {
            "exists": True,
            "path": str(self.db_path),
            "updated_at": meta.get("updated_at", "unknown"),
            "record_count": count,
        }

    def _init_schema(self, conn: sqlite3.Connection) -> None:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vulns (
                id TEXT PRIMARY KEY,
                ecosystem TEXT,
                package TEXT,
                summary TEXT,
                details TEXT,
                affected_versions TEXT,
                severity TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_eco_pkg ON vulns (ecosystem, package)")

    def _download_and_index(self, conn: sqlite3.Connection, ecosystem: str, url: str) -> None:
        """Download a zip of OSV records and index them into SQLite."""
        import io
        import zipfile

        # Download
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = resp.read()

        # Unzip and parse
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            inserted = 0
            for name in zf.namelist():
                if not name.endswith(".json"):
                    continue
                try:
                    raw = zf.read(name)
                    osv = json.loads(raw)
                    self._index_osv_record(conn, ecosystem, osv)
                    inserted += 1
                except Exception:
                    continue
        console.print(f"  [green]  ✓ Indexed {inserted} {ecosystem} vulnerabilities[/]")

    def _index_osv_record(self, conn: sqlite3.Connection, ecosystem: str, osv: dict) -> None:
        """Insert a single OSV record into the database."""
        osv_id = osv.get("id", "")
        summary = osv.get("summary", "")
        details = osv.get("details", "")

        affected = osv.get("affected", [])
        for entry in affected:
            pkg = entry.get("package", {})
            pkg_name = pkg.get("name", "").lower()
            pkg_eco = pkg.get("ecosystem", ecosystem)

            # Collect affected version strings
            versions = []
            for rng in entry.get("ranges", []):
                for event in rng.get("events", []):
                    for key, val in event.items():
                        versions.append(str(val))
            affected_str = ",".join(versions) if versions else "*"

            try:
                conn.execute(
                    "INSERT OR REPLACE INTO vulns (id, ecosystem, package, summary, details, affected_versions) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (osv_id, pkg_eco, pkg_name, summary, details, affected_str),
                )
            except Exception:
                pass