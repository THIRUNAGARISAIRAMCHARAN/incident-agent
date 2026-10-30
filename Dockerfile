FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY inc_app.py inc_plan.py inc_trace.py main.py ./
ENV DB_PATH=/tmp/incident.db
# ONE worker; state is in SQLite, locks are per process
CMD ["sh","-c","uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1 --proxy-headers --forwarded-allow-ips='*'"]
