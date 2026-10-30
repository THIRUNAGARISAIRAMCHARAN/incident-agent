# Q4 - Observable Incident Triage agent

Routes: POST /v2/incidents, POST /v2/incidents/{runId}/receipts, GET /v2/incidents/{runId}. Pure ASGI + SQLite, no redirects.

Files: inc_app.py (API + state machine), inc_plan.py (model call + strict plan validation), inc_trace.py (OTLP from stored state),
main.py, requirements.txt, Dockerfile, test_inc.py (run: python3 test_inc.py).

Deploy on Render (Docker, Free, one instance). Env vars: AIPIPE_TOKEN (your token), MODEL (optional, default gpt-4.1-mini).
Submit the base URL: https://<service>.onrender.com/
