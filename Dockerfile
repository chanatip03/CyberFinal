# ============================================================
# Operation Ghost Logs — Dockerfile (Render-ready)
# ============================================================
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Render injects PORT env variable — default 10000
EXPOSE 10000

# Use gunicorn for production (NOT flask dev server)
CMD gunicorn --bind 0.0.0.0:${PORT:-10000} --workers 2 --timeout 120 app:app
