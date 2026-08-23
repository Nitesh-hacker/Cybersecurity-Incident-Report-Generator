# Deployment Guide

This app is packaged to deploy on any platform that runs a Docker container or a
`gunicorn`-served Python app. Below are the three easiest free/low-cost options,
in order of how simple they are. Pick one.

All three end with a **public HTTPS URL** you can share.

---

## Option A — Render.com (easiest, free tier, no credit card)

1. Push this project to a **GitHub repo** (see "Getting it onto GitHub" below).
2. Go to https://render.com → sign in with GitHub.
3. Click **New +** → **Blueprint**, and select your repo. Render will detect
   `render.yaml` in this project automatically and configure everything —
   build command, start command, and a generated `SECRET_KEY` — for you.
4. Click **Apply**. First deploy takes 2-3 minutes.
5. Your app is live at `https://incident-report-generator-XXXX.onrender.com`.

No `render.yaml`? Do it manually instead: **New +** → **Web Service** → connect
repo → Runtime: `Python 3` → Build command: `pip install -r requirements.txt` →
Start command: `gunicorn --bind 0.0.0.0:$PORT app:app`.

*Free-tier note: Render's free web services spin down after 15 minutes of
inactivity and take ~30s to wake back up on the next request. Fine for a demo,
not for something that needs to always be instantly warm.*

---

## Option B — Fly.io (Docker-based, generous free allowance)

```bash
# Install the CLI (one-time)
curl -L https://fly.io/install.sh | sh

fly auth login
cd incident-report-generator
fly launch --no-deploy      # detects fly.toml, creates the app
fly secrets set SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
fly deploy
```

Fly builds the included `Dockerfile` and deploys it. Your app is live at
`https://incident-report-generator.fly.dev`.

---

## Option C — Any Docker host (Railway, DigitalOcean App Platform, AWS App Runner, etc.)

The `Dockerfile` in this project works unmodified on any container platform:

```bash
docker build -t incident-report-generator .
docker run -p 8000:8000 -e SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))") incident-report-generator
```

Push the image to your platform's registry (or connect the GitHub repo directly —
most platforms, including Railway and DigitalOcean, build the Dockerfile for you
automatically when you point them at the repo).

---

## Getting it onto GitHub (needed for Options A and C via repo-connect)

```bash
cd incident-report-generator
git init
git add .
git commit -m "Initial commit: incident report generator"
gh repo create incident-report-generator --public --source=. --push
# or manually: create a repo on github.com, then
#   git remote add origin https://github.com/<you>/incident-report-generator.git
#   git branch -M main && git push -u origin main
```

---

## Production checklist before sharing the URL

- [ ] `SECRET_KEY` is set as a real environment variable/secret on the host (all
      three options above do this for you) — don't rely on the random
      per-process fallback in a multi-instance deployment, since each instance
      would get a different key.
- [ ] Confirm `FLASK_DEBUG` is unset or `"0"` on the host (all configs above
      already do this).
- [ ] If you expect real traffic, put the app behind your organization's
      auth/SSO — this MVP has no login layer (see README "Known Limitations").
- [ ] The in-process rate limiter and audit log are per-instance. If you scale
      to multiple instances/workers beyond gunicorn's local workers, move
      rate-limit state to Redis and ship `audit.log` to centralized logging.

## Verifying the deployment

Once live, confirm the security headers and a report generation both work:

```bash
curl -sI https://<your-app-url>/ | grep -i x-frame-options
curl -X POST https://<your-app-url>/api/generate \
  -H "Content-Type: application/json" \
  -d '{"incident_id":"INC-TEST","title":"Deploy check","severity":"Low","status":"Open","classification":"TLP:GREEN","reported_by":"you","report_author":"you","date_reported":"2026-08-19","date_occurred":"2026-08-19","affected_systems":"n/a","description":"Verifying live deployment."}'
```
