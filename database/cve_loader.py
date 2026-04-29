import json
import os
import re
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

_DB_DIR = os.path.dirname(os.path.abspath(__file__))
_CVE_ROOT = os.path.join(_DB_DIR, "CVEs", "CVE_2025_26")
_CVE_CACHE_PATH = os.path.join(_CVE_ROOT, "_cve_cache.json")

@dataclass
class CVERecord:
    """
    Normalised CVE record used throughout the exploitation subsystem.
    """
    cve_id: str
    service_pattern: str
    description: str
    severity: str                     
    base_score: float                  
    affected_versions: List[str] = field(default_factory=list)
    _parsed_constraints: List[Tuple[str, tuple]] = field(
        default_factory=list, repr=False
    )

    def __post_init__(self):
        """Parse version constraint strings into comparable tuples."""
        self._parsed_constraints = []
        for v in self.affected_versions:
            parsed = _parse_version_constraint(v)
            if parsed:
                self._parsed_constraints.append(parsed)


# Regex: optional operator prefix (<, <=, >, >=, =) then a version string.
# Handles formats like "<4.21.9", "<=V8.0", "<6.0.2", "12.2.1.4.0", "< 5.22.9"
_VERSION_RE = re.compile(
    r'^\s*'
    r'(?P<op>[<>=!]+)?\s*'        
    r'[vV]?\s*'                   
    r'(?P<ver>[\d]+(?:\.[\d]+)*)' 
    r'\s*$'
)
# Regex to extract version numbers from banner strings.
_BANNER_VERSION_RE = re.compile(
    r'[vV]?(\d+(?:\.\d+){1,5})'
)
def _parse_version_string(version_str: str) -> Optional[tuple]:
    """
    Parse a dotted version string into a tuple of ints for comparison.
    """
    version_str = version_str.strip().lstrip("vV").strip()
    m = re.match(r'^(\d+(?:\.\d+)*)$', version_str)
    if not m:
        return None
    try:
        return tuple(int(x) for x in m.group(1).split("."))
    except ValueError:
        return None
def _parse_version_constraint(constraint_str: str) -> Optional[Tuple[str, tuple]]:
    """Parse a version constraint string into (operator, version_tuple)
    """
    constraint_str = constraint_str.strip()
    if not constraint_str or constraint_str == "<*" or constraint_str == "*":
        return None  

    m = _VERSION_RE.match(constraint_str)
    if not m:
        return None

    op = m.group("op") or "="
    ver_str = m.group("ver")
    try:
        ver_tuple = tuple(int(x) for x in ver_str.split("."))
    except ValueError:
        return None

    return (op, ver_tuple)


def version_in_range(version_str: str, cve_record: CVERecord) -> bool:
    """
    Check if a discovered version falls within a CVE's affected range.
    """
    target = _parse_version_string(version_str)
    if target is None:
        return True
    if not cve_record.affected_versions:
        return True
    if not cve_record._parsed_constraints:
        return True
    for op, constraint_ver in cve_record._parsed_constraints:
        max_len = max(len(target), len(constraint_ver))
        t = target + (0,) * (max_len - len(target))
        c = constraint_ver + (0,) * (max_len - len(constraint_ver))
        if op == "<" and t < c:
            return True
        elif op == "<=" and t <= c:
            return True
        elif op == ">" and t > c:
            return True
        elif op == ">=" and t >= c:
            return True
        elif op == "=" and t == c:
            return True
        elif op == "==" and t == c:
            return True

    return False


def extract_versions_from_banner(banner: str) -> List[str]:
    """
    Extract all version-like strings from a service banner.
    """
    seen = set()
    versions = []
    for m in _BANNER_VERSION_RE.finditer(banner):
        v = m.group(1)
        if v not in seen:
            seen.add(v)
            versions.append(v)
    return versions

class CVEDatabase:
    """
    In-memory CVE database loaded from the local cache and JSON files.
    """
    def __init__(self, cache_path: str = _CVE_CACHE_PATH):
        self._records: List[CVERecord] = []
        self._by_pattern: Dict[str, List[CVERecord]] = {}
        self._by_id: Dict[str, CVERecord] = {}
        self._loaded = False
        self._cache_path = cache_path
        self._load_cache()
    def _load_cache(self) -> None:
        """
        Load the pre-built CVE cache into memory.
        """
        if not os.path.isfile(self._cache_path):
            logger.warning(f"CVE cache not found at {self._cache_path}")
            return
        try:
            with open(self._cache_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.error(f"Failed to load CVE cache: {e}")
            return
        entries = data.get("entries", [])
        for entry in entries:
            record = CVERecord(
                cve_id=entry["cve_id"],
                service_pattern=entry["service_pattern"],
                description=entry.get("description", ""),
                severity=entry.get("severity", "medium"),
                base_score=entry.get("base_score", 0.0),
                affected_versions=entry.get("affected_versions", []),
            )
            self._records.append(record)
            self._by_id[record.cve_id] = record
            pattern = record.service_pattern.lower()
            if pattern not in self._by_pattern:
                self._by_pattern[pattern] = []
            self._by_pattern[pattern].append(record)
        self._loaded = True
        logger.info(
            f"CVE database loaded: {len(self._records)} records, "
            f"{len(self._by_pattern)} service patterns"
        )
    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def record_count(self) -> int:
        return len(self._records)

    @property
    def service_patterns(self) -> List[str]:
        """Return all known service patterns in the database."""
        return sorted(self._by_pattern.keys())

    def get_by_id(self, cve_id: str) -> Optional[CVERecord]:
        """Look up a single CVE by its ID."""
        return self._by_id.get(cve_id)

    def lookup(self, service_pattern: str) -> List[CVERecord]:
        """Find all CVEs matching a service pattern (exact match on the key)."""
        return self._by_pattern.get(service_pattern.lower(), [])

    def search(self, text: str) -> List[CVERecord]:
        """
        Find CVEs whose service_pattern is a substring of the given text.
        """
        text_lower = text.lower()
        results = []
        for pattern, records in self._by_pattern.items():
            if pattern in text_lower:
                results.extend(records)
        return results

    def match_banner(self, banner: str, port: int = 0,
                     service_hint: str = "") -> List[dict]:
        """
        Match a service banner against the CVE database with version checking
        """
        search_text = f"{banner} {service_hint}".lower()
        candidate_records = self.search(search_text)

        if not candidate_records:
            return []

        # Extract versions from the banner for range checking.
        banner_versions = extract_versions_from_banner(banner)

        matches = []
        seen_cves = set()

        for record in candidate_records:
            if record.cve_id in seen_cves:
                continue
            seen_cves.add(record.cve_id)

            # Determine version match status and confidence.
            version_matched = False
            matched_version = ""
            confidence = 0.0

            if not record.affected_versions:
                # No version constraints → all versions affected.
                # Pattern match alone gives moderate confidence.
                version_matched = True
                matched_version = "all"
                confidence = 0.5
            elif banner_versions:
                # Check each extracted version against the CVE constraints.
                for v in banner_versions:
                    if version_in_range(v, record):
                        version_matched = True
                        matched_version = v
                        # Pattern + version match → high confidence.
                        confidence = 0.8
                        break
                if not version_matched:
                    # Pattern matched but version is outside the affected range.
                    confidence = 0.3
            else:
                # No version extractable from banner — pattern match only.
                confidence = 0.4

            # Boost confidence for critical CVEs
            if record.severity == "critical" and confidence > 0:
                confidence = min(confidence + 0.1, 0.95)

            matches.append({
                "cve_id": record.cve_id,
                "description": record.description,
                "severity": record.severity,
                "base_score": record.base_score,
                "matched_pattern": record.service_pattern,
                "affected_versions": record.affected_versions,
                "version_match": version_matched,
                "matched_version": matched_version,
                "confidence": round(confidence, 2),
            })

        matches.sort(key=lambda m: (-m["version_match"], -m["base_score"]))
        return matches

    def load_full_cve_record(self, cve_id: str) -> Optional[dict]:
        """
        Load the full NVD JSON record for a CVE from disk.
        """
        # Parse year and sequence from the CVE ID.
        parts = cve_id.split("-")
        if len(parts) != 3:
            return None

        year = parts[1]
        seq = int(parts[2])
        # Map sequence to the directory bucket (0xxx, 1xxx, ..., 71xxx).
        bucket = f"{(seq // 1000) * 1000 if seq >= 1000 else 0}"
        # Pad to match directory naming: "0xxx", "1xxx", "10xxx", etc.
        bucket_dir = f"{seq // 1000}xxx"

        json_path = os.path.join(_CVE_ROOT, year, bucket_dir, f"{cve_id}.json")

        if not os.path.isfile(json_path):
            logger.debug(f"Full CVE record not found: {json_path}")
            return None

        try:
            with open(json_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.error(f"Failed to load {json_path}: {e}")
            return None
