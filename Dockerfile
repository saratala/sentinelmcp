FROM python:3.12-slim AS base

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[test]"

COPY . .

# ── api (default) ─────────────────────────────────────────────────────────────
FROM base AS api
EXPOSE 8888
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8888"]

# ── celery worker ─────────────────────────────────────────────────────────────
FROM base AS worker
CMD ["celery", "-A", "worker.tasks", "worker", "--loglevel=info", "--concurrency=4"]

# ── demo servers ──────────────────────────────────────────────────────────────
FROM base AS demo-clean
EXPOSE 8001
CMD ["python", "demo/clean_server.py"]

FROM base AS demo-poisoned
EXPOSE 8002
CMD ["python", "demo/poisoned_server.py"]

# ── React dashboard ───────────────────────────────────────────────────────────
FROM node:20-alpine AS dashboard
WORKDIR /app
COPY dashboard/package*.json ./
RUN npm ci
COPY dashboard/ .
ARG VITE_SENTINEL_API_KEY=dev-key-123
ENV VITE_SENTINEL_API_KEY=${VITE_SENTINEL_API_KEY}
RUN npm run build

FROM nginx:alpine AS dashboard-serve
COPY --from=dashboard /app/dist /usr/share/nginx/html
COPY dashboard/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 5173
