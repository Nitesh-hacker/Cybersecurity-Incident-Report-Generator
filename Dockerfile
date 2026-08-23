# Cybersecurity Incident Report Generator - production image
FROM python:3.12-slim

# Run as a non-root user (defense in depth: limits blast radius if the
# container is ever compromised).
RUN useradd --create-home --uid 1000 appuser
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chown -R appuser:appuser /app
USER appuser

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

EXPOSE 8000

# gunicorn, not the Flask dev server: multi-worker, production-grade
# WSGI server. --workers 2 is a sane default for a free-tier instance;
# raise it if you have more CPU. Bind 0.0.0.0 so the container's
# published port is reachable from outside.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--timeout", "30", "app:app"]
