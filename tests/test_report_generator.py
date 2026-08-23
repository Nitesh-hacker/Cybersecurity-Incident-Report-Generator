"""
Unit tests for the Incident Report Generator.
Run with:  pytest -v
"""

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from security import (
    validate_incident_data, sanitize_text, ValidationError,
    compute_integrity_hash, verify_integrity_hash, RateLimiter,
)
from report_generator import build_report, render_markdown, render_pdf


def _valid_payload(**overrides):
    payload = {
        "incident_id": "INC-2026-0142",
        "title": "Phishing-driven credential compromise",
        "severity": "High",
        "status": "Investigating",
        "classification": "TLP:AMBER",
        "reported_by": "SOC Analyst",
        "report_author": "Jane Doe",
        "date_reported": "2026-08-18",
        "date_occurred": "2026-08-17",
        "affected_systems": "mail-gw-02, corp-vpn-01",
        "description": "User clicked a phishing link and entered credentials on a spoofed portal.",
        "timeline": [
            {"timestamp": "2026-08-17 09:14", "description": "Suspicious login flagged by SIEM"},
            {"timestamp": "2026-08-17 09:40", "description": "Account disabled"},
        ],
        "indicators_of_compromise": ["185.220.101.44", "malicious-login-portal.example"],
        "impact_assessment": "One account compromised, no lateral movement observed.",
        "containment_actions": "Disabled account, reset credentials, blocked IOC domain.",
        "recommendations": "Enable phishing-resistant MFA org-wide.",
    }
    payload.update(overrides)
    return payload


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
class TestValidation:
    def test_valid_payload_passes(self):
        cleaned = validate_incident_data(_valid_payload())
        assert cleaned["incident_id"] == "INC-2026-0142"
        assert cleaned["severity"] == "High"

    def test_missing_required_field_rejected(self):
        payload = _valid_payload()
        del payload["title"]
        with pytest.raises(ValidationError) as exc:
            validate_incident_data(payload)
        assert any("title" in e for e in exc.value.errors)

    def test_invalid_severity_rejected(self):
        with pytest.raises(ValidationError) as exc:
            validate_incident_data(_valid_payload(severity="SuperBad"))
        assert any("severity" in e for e in exc.value.errors)

    def test_invalid_status_rejected(self):
        with pytest.raises(ValidationError):
            validate_incident_data(_valid_payload(status="Vibing"))

    def test_invalid_classification_rejected(self):
        with pytest.raises(ValidationError):
            validate_incident_data(_valid_payload(classification="TLP:PURPLE"))

    def test_bad_incident_id_charset_rejected(self):
        with pytest.raises(ValidationError):
            validate_incident_data(_valid_payload(incident_id="INC 2026; DROP TABLE"))

    def test_bad_date_format_rejected(self):
        with pytest.raises(ValidationError):
            validate_incident_data(_valid_payload(date_reported="not-a-date"))

    def test_oversized_field_rejected(self):
        with pytest.raises(ValidationError):
            validate_incident_data(_valid_payload(title="A" * 500))

    def test_non_dict_payload_rejected(self):
        with pytest.raises(ValidationError):
            validate_incident_data(["not", "a", "dict"])

    def test_timeline_must_be_list(self):
        with pytest.raises(ValidationError):
            validate_incident_data(_valid_payload(timeline="not a list"))

    def test_too_many_timeline_events_truncated_with_error(self):
        payload = _valid_payload(timeline=[
            {"timestamp": "2026-01-01", "description": f"event {i}"} for i in range(300)
        ])
        with pytest.raises(ValidationError) as exc:
            validate_incident_data(payload)
        assert any("timeline" in e for e in exc.value.errors)

    def test_iocs_must_be_list(self):
        with pytest.raises(ValidationError):
            validate_incident_data(_valid_payload(indicators_of_compromise="1.2.3.4"))


# ---------------------------------------------------------------------------
# Sanitization / injection resistance
# ---------------------------------------------------------------------------
class TestSanitization:
    def test_script_tag_escaped(self):
        result = sanitize_text("<script>alert('xss')</script>")
        assert "<script>" not in result
        assert "&lt;script&gt;" in result

    def test_control_characters_stripped(self):
        result = sanitize_text("hello\x00\x08world")
        assert "\x00" not in result and "\x08" not in result

    def test_full_payload_with_xss_attempt_is_neutralized(self):
        payload = _valid_payload(
            description="Normal text <img src=x onerror=alert(1)> more text",
            title="Report <script>steal_cookies()</script>",
        )
        cleaned = validate_incident_data(payload)
        assert "<script>" not in cleaned["title"]
        assert "onerror=" in cleaned["description"]  # text preserved
        assert "<img" not in cleaned["description"]  # but not as live HTML

    def test_sql_like_string_in_free_text_is_just_escaped_text(self):
        # We don't touch a database with raw strings anywhere in this
        # app (no string-built SQL at all), but confirm such input is
        # still safely treated as inert text end-to-end.
        payload = _valid_payload(affected_systems="server1'; DROP TABLE incidents; --")
        cleaned = validate_incident_data(payload)
        report = build_report(cleaned)
        md, _ = render_markdown(report)
        assert "DROP TABLE" in md  # preserved as literal text, not executed


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------
class TestReportGeneration:
    def test_markdown_contains_key_fields(self):
        cleaned = validate_incident_data(_valid_payload())
        report = build_report(cleaned)
        md, integrity_hash = render_markdown(report)
        assert "INC-2026-0142" in md
        assert "Phishing-driven credential compromise" in md
        assert integrity_hash in md
        assert len(integrity_hash) == 64  # sha256 hex digest length

    def test_pdf_generation_produces_nonempty_bytes(self):
        cleaned = validate_incident_data(_valid_payload())
        report = build_report(cleaned)
        md, _ = render_markdown(report)
        pdf_bytes = render_pdf(report, md)
        assert pdf_bytes[:4] == b"%PDF"
        assert len(pdf_bytes) > 500

    def test_empty_timeline_and_iocs_handled_gracefully(self):
        payload = _valid_payload(timeline=[], indicators_of_compromise=[])
        cleaned = validate_incident_data(payload)
        report = build_report(cleaned)
        md, _ = render_markdown(report)
        assert "No timeline events recorded" in md
        assert "No IOCs recorded" in md


# ---------------------------------------------------------------------------
# Integrity hashing
# ---------------------------------------------------------------------------
class TestIntegrity:
    def test_hash_is_deterministic(self):
        text = "some report content"
        assert compute_integrity_hash(text) == compute_integrity_hash(text)

    def test_hash_changes_when_content_changes(self):
        h1 = compute_integrity_hash("report v1")
        h2 = compute_integrity_hash("report v2")
        assert h1 != h2

    def test_verify_integrity_detects_tampering(self):
        text = "original report content"
        h = compute_integrity_hash(text)
        assert verify_integrity_hash(text, h) is True
        assert verify_integrity_hash("tampered report content", h) is False


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
class TestRateLimiter:
    def test_allows_up_to_limit(self):
        limiter = RateLimiter(max_requests=3, window_seconds=60)
        key = "test-client"
        assert limiter.allow(key) is True
        assert limiter.allow(key) is True
        assert limiter.allow(key) is True

    def test_blocks_beyond_limit(self):
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        key = "test-client-2"
        assert limiter.allow(key) is True
        assert limiter.allow(key) is True
        assert limiter.allow(key) is False

    def test_different_keys_independent(self):
        limiter = RateLimiter(max_requests=1, window_seconds=60)
        assert limiter.allow("client-a") is True
        assert limiter.allow("client-b") is True  # separate bucket
        assert limiter.allow("client-a") is False


# ---------------------------------------------------------------------------
# Flask endpoints (integration-style, using Flask test client)
# ---------------------------------------------------------------------------
class TestApiEndpoints:
    @pytest.fixture
    def client(self):
        import app as flask_app_module
        flask_app_module.app.config["TESTING"] = True
        return flask_app_module.app.test_client()

    def test_index_loads(self, client):
        resp = client.get("/")
        assert resp.status_code == 200

    def test_generate_valid_payload(self, client):
        resp = client.post("/api/generate", json=_valid_payload())
        assert resp.status_code == 200
        data = resp.get_json()
        assert "integrity_hash" in data
        assert "markdown" in data

    def test_generate_invalid_payload_returns_422(self, client):
        bad = _valid_payload()
        del bad["title"]
        resp = client.post("/api/generate", json=bad)
        assert resp.status_code == 422
        assert "details" in resp.get_json()

    def test_generate_non_json_rejected(self, client):
        resp = client.post("/api/generate", data="not json", content_type="text/plain")
        assert resp.status_code == 400

    def test_security_headers_present(self, client):
        resp = client.get("/")
        assert resp.headers.get("X-Frame-Options") == "DENY"
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert "Content-Security-Policy" in resp.headers

    def test_pdf_endpoint_returns_pdf(self, client):
        resp = client.post("/api/generate_pdf", json=_valid_payload())
        assert resp.status_code == 200
        assert resp.content_type == "application/pdf"
        assert resp.data[:4] == b"%PDF"
