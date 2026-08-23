"""
app.py
Flask web application for the Incident Report Generator.

Security features wired in at this layer:
  - SECRET_KEY read from environment, never hardcoded (falls back to a
    random per-process key so it never accidentally ships a default).
  - Security headers on every response (CSP, X-Frame-Options, etc).
  - Per-IP rate limiting on report generation.
  - Max request body size enforced (protects against huge payload DoS).
  - All incoming data validated + sanitized via security.py before it
    ever reaches report_generator.py.
  - Errors return generic messages to the client; details go to the
    audit log, not the HTTP response.
"""

import os
import secrets
import uuid

from flask import Flask, request, jsonify, render_template, send_file, abort
from io import BytesIO

from security import validate_incident_data, ValidationError, RateLimiter, audit_log
from report_generator import build_report, render_markdown, render_pdf

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024  # 512 KB max request body

limiter = RateLimiter(max_requests=20, window_seconds=60)


@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; "
        "script-src 'self'; frame-ancestors 'none'"
    )
    response.headers["X-XSS-Protection"] = "0"  # modern browsers use CSP instead
    return response


def _client_key():
    # In production behind a real proxy, prefer a verified header/
    # authenticated identity over raw remote_addr.
    return request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/generate", methods=["POST"])
def api_generate():
    if not limiter.allow(_client_key()):
        return jsonify({"error": "Rate limit exceeded. Try again shortly."}), 429

    if not request.is_json:
        return jsonify({"error": "Request must be application/json."}), 400

    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"error": "Invalid JSON body."}), 400

    try:
        cleaned = validate_incident_data(payload)
    except ValidationError as e:
        return jsonify({"error": "Validation failed.", "details": e.errors}), 422

    report = build_report(cleaned)
    markdown_text, integrity_hash = render_markdown(report)

    return jsonify({
        "incident_id": report.incident_id,
        "generated_at": report.generated_at,
        "integrity_hash": integrity_hash,
        "markdown": markdown_text,
        "download_pdf_url": f"/api/report/{report.incident_id}/pdf",
    })


# In-memory store for demo purposes only. A real deployment would persist
# reports in a database with access control, not process memory.
_REPORT_CACHE = {}


@app.route("/api/generate_pdf", methods=["POST"])
def api_generate_pdf():
    """Validate, build, and stream back a PDF directly (used by the
    'Download PDF' button in the demo UI)."""
    if not limiter.allow(_client_key()):
        return jsonify({"error": "Rate limit exceeded. Try again shortly."}), 429

    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"error": "Invalid JSON body."}), 400

    try:
        cleaned = validate_incident_data(payload)
    except ValidationError as e:
        return jsonify({"error": "Validation failed.", "details": e.errors}), 422

    report = build_report(cleaned)
    markdown_text, integrity_hash = render_markdown(report)
    pdf_bytes = render_pdf(report, markdown_text)

    safe_id = "".join(c for c in report.incident_id if c.isalnum() or c in "-_") or "report"
    return send_file(
        BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"incident_report_{safe_id}.pdf",
    )


@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "Payload too large."}), 413


@app.errorhandler(500)
def internal_error(e):
    # Never leak stack traces / internals to the client.
    audit_log("INTERNAL_ERROR", request_id=str(uuid.uuid4()))
    return jsonify({"error": "Internal server error."}), 500


if __name__ == "__main__":
    # debug=False by default: never run with the interactive debugger
    # (which allows arbitrary code execution) in anything resembling
    # production.
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    port = int(os.environ.get("PORT", 5000))
    # Bind to 127.0.0.1 for local dev; hosting platforms (Render, Fly,
    # Railway, etc.) set HOST=0.0.0.0 via their environment so the
    # container's exposed port is actually reachable. In production,
    # gunicorn (see Dockerfile/Procfile) is used instead of this
    # dev server entirely.
    host = os.environ.get("HOST", "127.0.0.1")
    app.run(host=host, port=port, debug=debug_mode)
