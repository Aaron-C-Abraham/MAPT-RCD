import os
import re
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

_DB_DIR = os.path.dirname(os.path.abspath(__file__))
_NMAP_OS_DB_PATH = os.path.join(_DB_DIR, "nmap-os-db.txt")


@dataclass
class NmapOSSignature:
    """A parsed nmap OS fingerprint signature."""
    name: str                   
    vendor: str = ""            
    os_family: str = ""         
    os_gen: str = ""         
    device_type: str = ""       
    cpe: str = ""               
    # TCP fingerprint fields (from T1/WIN/OPS lines)
    ttl_guess: int = 0          # Initial TTL (TG from T1 line: FF=255, 40=64, 80=128)
    df: Optional[bool] = None   # Don't Fragment bit (Y/N from T1)
    window: int = 0             # TCP window size (W1 from WIN line)
    window_range: Tuple[int, int] = (0, 0)  # Window size range if specified
    options: str = ""           # TCP options string (O1 from OPS line)
    has_wscale: bool = False
    has_sack: bool = False
    has_timestamp: bool = False


def _parse_hex_range(value: str) -> Tuple[int, int]:
    """Parse a nmap hex value or range like 'FFFF' or '7FFF-8FFF'."""
    if "-" in value:
        parts = value.split("-", 1)
        try:
            return (int(parts[0], 16), int(parts[1], 16))
        except ValueError:
            return (0, 0)
    try:
        v = int(value, 16)
        return (v, v)
    except ValueError:
        return (0, 0)


def _parse_test_line(line: str) -> Dict[str, str]:
    """Parse a nmap test line like 'T1(R=Y%DF=Y%T=3B-45%TG=40%...)' into a dict."""
    result = {}
    # Extract content between parentheses
    m = re.match(r'^\w+\((.+)\)$', line.strip())
    if not m:
        return result
    for pair in m.group(1).split("%"):
        if "=" in pair:
            key, val = pair.split("=", 1)
            result[key] = val
    return result


def load_nmap_os_db(path: str = _NMAP_OS_DB_PATH) -> List[NmapOSSignature]:
    """Parse nmap-os-db.txt and return a list of OS signatures.

    Only extracts the fields relevant to simple TCP SYN-ACK fingerprinting
    (TTL, window size, DF bit, TCP options).
    """
    if not os.path.isfile(path):
        logger.warning(f"Nmap OS DB not found: {path}")
        return []

    signatures = []
    current_name = ""
    current_class = {"vendor": "", "os_family": "", "os_gen": "", "device_type": ""}
    current_cpe = ""
    current_t1 = {}
    current_win = {}
    current_ops = {}

    def _flush():
        nonlocal current_name, current_class, current_cpe, current_t1, current_win, current_ops
        if not current_name:
            return

        sig = NmapOSSignature(name=current_name)
        sig.vendor = current_class.get("vendor", "")
        sig.os_family = current_class.get("os_family", "")
        sig.os_gen = current_class.get("os_gen", "")
        sig.device_type = current_class.get("device_type", "")
        sig.cpe = current_cpe

        # Parse TTL from T1.TG (initial TTL guess, in hex)
        tg = current_t1.get("TG", "")
        if tg:
            try:
                sig.ttl_guess = int(tg, 16)
            except ValueError:
                pass

        # Parse DF from T1.DF
        df = current_t1.get("DF", "")
        if df == "Y":
            sig.df = True
        elif df == "N":
            sig.df = False

        # Parse window from WIN.W1
        w1 = current_win.get("W1", "")
        if w1:
            low, high = _parse_hex_range(w1)
            sig.window = low
            sig.window_range = (low, high)

        # Parse TCP options from OPS.O1
        o1 = current_ops.get("O1", "")
        if o1:
            sig.options = o1
            sig.has_wscale = "W" in o1
            sig.has_sack = "S" in o1
            sig.has_timestamp = "T" in o1

        # Only add signatures that have useful matching data
        if sig.ttl_guess > 0 or sig.window > 0:
            signatures.append(sig)

        # Reset
        current_name = ""
        current_class = {"vendor": "", "os_family": "", "os_gen": "", "device_type": ""}
        current_cpe = ""
        current_t1 = {}
        current_win = {}
        current_ops = {}

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line or line.startswith("#"):
                    continue

                if line.startswith("Fingerprint "):
                    _flush()
                    current_name = line[len("Fingerprint "):].strip()

                elif line.startswith("Class "):
                    # Format: Class vendor | os_family | os_gen | device_type
                    parts = line[len("Class "):].split("|")
                    parts = [p.strip() for p in parts]
                    if len(parts) >= 1:
                        current_class["vendor"] = parts[0]
                    if len(parts) >= 2:
                        current_class["os_family"] = parts[1]
                    if len(parts) >= 3:
                        current_class["os_gen"] = parts[2]
                    if len(parts) >= 4:
                        current_class["device_type"] = parts[3]

                elif line.startswith("CPE "):
                    current_cpe = line[len("CPE "):].strip()

                elif line.startswith("T1("):
                    current_t1 = _parse_test_line(line)

                elif line.startswith("WIN("):
                    current_win = _parse_test_line(line)

                elif line.startswith("OPS("):
                    current_ops = _parse_test_line(line)

        _flush()  # Don't forget the last entry
    except OSError as e:
        logger.error(f"Failed to read nmap OS DB: {e}")
        return []

    logger.info(f"Loaded {len(signatures)} OS signatures from nmap-os-db.txt")
    return signatures


class NmapOSMatcher:
    """
    Match TCP/IP fingerprints against the nmap OS signature database
    """

    def __init__(self, signatures: Optional[List[NmapOSSignature]] = None):
        if signatures is None:
            signatures = load_nmap_os_db()
        self._signatures = signatures
        # Build TTL index for fast lookup
        self._by_ttl: Dict[int, List[NmapOSSignature]] = {}
        for sig in self._signatures:
            ttl = sig.ttl_guess
            if ttl not in self._by_ttl:
                self._by_ttl[ttl] = []
            self._by_ttl[ttl].append(sig)

    @property
    def signature_count(self) -> int:
        return len(self._signatures)

    def match(self, ttl: int, window: int, df: bool,
              has_wscale: bool = False, has_sack: bool = False,
              has_timestamp: bool = False, top_n: int = 5) -> List[dict]:
        """Match a TCP fingerprint against the database.
        """
        # Infer initial TTL
        if ttl <= 32:
            initial_ttl = 32
        elif ttl <= 64:
            initial_ttl = 64
        elif ttl <= 128:
            initial_ttl = 128
        else:
            initial_ttl = 255

        # Score all signatures that match the initial TTL
        candidates = self._by_ttl.get(initial_ttl, [])
        # Also check nearby TTLs for robustness
        if not candidates:
            candidates = self._signatures

        scored = []
        for sig in candidates:
            score = 0
            max_score = 95

            # TTL match (40 points)
            if sig.ttl_guess == initial_ttl:
                score += 40
            elif sig.ttl_guess > 0:
                continue  # Skip non-matching TTLs for efficiency

            # Window match (30 points)
            if sig.window_range[1] > 0:
                if sig.window_range[0] <= window <= sig.window_range[1]:
                    score += 30
                elif sig.window > 0:
                    # Partial credit for nearby windows
                    ratio = min(window, sig.window) / max(window, sig.window, 1)
                    if ratio > 0.8:
                        score += int(20 * ratio)
            elif sig.window > 0:
                if window == sig.window:
                    score += 30
                else:
                    ratio = min(window, sig.window) / max(window, sig.window, 1)
                    if ratio > 0.8:
                        score += int(20 * ratio)

            # DF match (10 points)
            if sig.df is not None and sig.df == df:
                score += 10

            # TCP options (5 points each)
            if sig.has_wscale == has_wscale:
                score += 5
            if sig.has_sack == has_sack:
                score += 5
            if sig.has_timestamp == has_timestamp:
                score += 5

            if score > 30:  # Minimum threshold
                confidence = round(score / max_score, 2)
                scored.append({
                    "name": sig.name,
                    "vendor": sig.vendor,
                    "os_family": sig.os_family,
                    "os_gen": sig.os_gen,
                    "device_type": sig.device_type,
                    "cpe": sig.cpe,
                    "score": score,
                    "confidence": confidence,
                })

        # Sort by score descending, take top N
        scored.sort(key=lambda x: -x["score"])
        return scored[:top_n]
