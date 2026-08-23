"""
security.py
All input-trust-boundary logic lives here, in one place, so it can be
audited and unit-tested independently of the web layer or the report
renderer.

Design principles applied:
  1. Allow-list validation over block-list filtering wherever possible.
  2. Sanitize *before* the data reaches templates (defense in depth even
     though Jinja2 autoescapes -- we don't want raw HTML/script content
     persisted into saved reports either).
  3. Fail closed: invalid input raises ValidationError instead of being
     coerced into "something safe-looking".
  4. Every report gets a SHA-256 integrity hash computed *after*
     sanitization so tampering with a saved report is detectable.
  5. Security-relevant events (report generated, validation failure,
     rate limit hit) are logged to an append-only audit log, with
     sensitive free-text fields excluded from the log line itself.
"""

import hashlib
import hmac
import html
import logging
import re
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from models import (
    SEVERITY_LEVELS,
    STATUS_VALUES,
    TLP_LEVELS,
    FIELD_LIMITS,
    TIMELINE_ENTRY_LIMIT,
    IOC_ENTRY_LIMIT,
    MAX_TIMELINE_EVENTS,
    MAX_IOCS,
)

# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("incident_report_audit")
logger.setLevel(logging.INFO)
if not logger.handlers:
    _handler = logging.FileHandler("audit.log")
    _handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
    logger.addHandler(_handler)


def audit_log(event: str, **meta):
    """Log a security-relevant event without including raw free-text
    report content (only IDs, counts, and outcomes)."""
    safe_meta = " ".join(f"{k}={v}" for k, v in meta.items())
    logger.info("%s | %s", event, safe_meta)


class ValidationError(Exception):
    """Raised when incoming data fails validation. Carries a list of
    human-readable, non-sensitive error messages."""

    def __init__(self, errors):
        self.errors = errors if isinstance(errors, list) else [errors]
        super().__init__("; ".join(self.errors))


# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_text(value: str) -> str:
    """Strip control characters and HTML-escape user-supplied text.

    We escape rather than try to allow a safe subset of HTML: incident
    report free-text fields have no legitimate need for markup, and
    escaping is far less likely to have bypasses than a hand-rolled
    HTML sanitizer/allow-list.
    """
    if value is None:
        return ""
    value = str(value)
    value = _CONTROL_CHARS.sub("", value)
    value = value.strip()
    value = html.escape(value, quote=True)
    return value


def _check_len(name, value, limit, errors):
    if len(value) > limit:
        errors.append(f"'{name}' exceeds max length of {limit} characters "
                       f"(got {len(value)}).")


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
REQUIRED_FIELDS = [
    "incident_id", "title", "severity", "status", "classification",
    "reported_by", "report_author", "date_reported", "date_occurred",
    "affected_systems", "description",
]

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2})?)?$")
_INCIDENT_ID_RE = re.compile(r"^[A-Za-z0-9\-_]+$")


def validate_incident_data(raw: dict) -> dict:
    """Validate + sanitize a raw (untrusted) incident payload.

    Returns a cleaned dict ready to build an IncidentReport. Raises
    ValidationError with a full list of problems (not just the first
    one) so a caller/UI can show everything at once.
    """
    errors = []
    if not isinstance(raw, dict):
        raise ValidationError(["Payload must be a JSON object."])

    cleaned = {}

    for field_name in REQUIRED_FIELDS:
        if field_name not in raw or raw[field_name] in (None, ""):
            errors.append(f"'{field_name}' is required.")

    # Enum-constrained fields (allow-list)
    severity = str(raw.get("severity", ""))
    if severity not in SEVERITY_LEVELS:
        errors.append(f"'severity' must be one of {SEVERITY_LEVELS}.")
    cleaned["severity"] = severity if severity in SEVERITY_LEVELS else ""

    status = str(raw.get("status", ""))
    if status not in STATUS_VALUES:
        errors.append(f"'status' must be one of {STATUS_VALUES}.")
    cleaned["status"] = status if status in STATUS_VALUES else ""

    classification = str(raw.get("classification", ""))
    if classification not in TLP_LEVELS:
        errors.append(f"'classification' must be one of {TLP_LEVELS}.")
    cleaned["classification"] = classification if classification in TLP_LEVELS else ""

    # incident_id: restricted charset, no free text
    incident_id = str(raw.get("incident_id", "")).strip()
    if incident_id and not _INCIDENT_ID_RE.match(incident_id):
        errors.append("'incident_id' may only contain letters, digits, '-' and '_'.")
    _check_len("incident_id", incident_id, FIELD_LIMITS["incident_id"], errors)
    cleaned["incident_id"] = incident_id

    # Dates: must look like ISO dates, not arbitrary strings
    for date_field in ("date_reported", "date_occurred"):
        value = str(raw.get(date_field, "")).strip()
        if value and not _DATE_RE.match(value):
            errors.append(f"'{date_field}' must be an ISO date (YYYY-MM-DD).")
        cleaned[date_field] = value

    # Free-text fields: length-check then sanitize
    for text_field in ("title", "reported_by", "report_author", "affected_systems",
                        "description", "root_cause", "impact_assessment",
                        "recommendations", "containment_actions",
                        "eradication_actions", "recovery_actions"):
        raw_value = str(raw.get(text_field, ""))
        limit = FIELD_LIMITS.get(text_field, 3000)
        _check_len(text_field, raw_value, limit, errors)
        cleaned[text_field] = sanitize_text(raw_value)

    # Timeline: list of {timestamp, description}
    timeline = raw.get("timeline", []) or []
    if not isinstance(timeline, list):
        errors.append("'timeline' must be a list.")
        timeline = []
    if len(timeline) > MAX_TIMELINE_EVENTS:
        errors.append(f"'timeline' may contain at most {MAX_TIMELINE_EVENTS} events.")
        timeline = timeline[:MAX_TIMELINE_EVENTS]
    cleaned_timeline = []
    for i, entry in enumerate(timeline):
        if not isinstance(entry, dict):
            errors.append(f"timeline[{i}] must be an object.")
            continue
        ts = str(entry.get("timestamp", ""))
        desc = str(entry.get("description", ""))
        _check_len(f"timeline[{i}].description", desc, TIMELINE_ENTRY_LIMIT, errors)
        cleaned_timeline.append({
            "timestamp": sanitize_text(ts)[:64],
            "description": sanitize_text(desc),
        })
    cleaned["timeline"] = cleaned_timeline

    # IOCs: list of strings
    iocs = raw.get("indicators_of_compromise", []) or []
    if not isinstance(iocs, list):
        errors.append("'indicators_of_compromise' must be a list.")
        iocs = []
    if len(iocs) > MAX_IOCS:
        errors.append(f"'indicators_of_compromise' may contain at most {MAX_IOCS} entries.")
        iocs = iocs[:MAX_IOCS]
    cleaned_iocs = []
    for i, ioc in enumerate(iocs):
        ioc_str = str(ioc)
        _check_len(f"indicators_of_compromise[{i}]", ioc_str, IOC_ENTRY_LIMIT, errors)
        cleaned_iocs.append(sanitize_text(ioc_str))
    cleaned["indicators_of_compromise"] = cleaned_iocs

    if errors:
        audit_log("VALIDATION_FAILED", error_count=len(errors))
        raise ValidationError(errors)

    return cleaned


# ---------------------------------------------------------------------------
# Integrity
# ---------------------------------------------------------------------------
def compute_integrity_hash(report_text: str) -> str:
    """SHA-256 hash of the final rendered report content, so recipients
    can verify a report hasn't been altered after generation."""
    return hashlib.sha256(report_text.encode("utf-8")).hexdigest()


def verify_integrity_hash(report_text: str, expected_hash: str) -> bool:
    computed = compute_integrity_hash(report_text)
    # Constant-time comparison to avoid timing side-channels on the check.
    return hmac.compare_digest(computed, expected_hash)


# ---------------------------------------------------------------------------
# Simple in-memory rate limiter (per client key, sliding window)
# ---------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, max_requests: int = 20, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.time()
        q = self._hits[key]
        while q and now - q[0] > self.window_seconds:
            q.popleft()
        if len(q) >= self.max_requests:
            audit_log("RATE_LIMIT_EXCEEDED", key=key)
            return False
        q.append(now)
        return True
