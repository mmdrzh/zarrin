# Web UI
FROM node:22-alpine AS web
WORKDIR /web
COPY panel/web/package.json panel/web/package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci --no-audit --no-fund; else npm install --no-audit --no-fund; fi
COPY panel/web/ ./
RUN npm run build

# Panel
FROM python:3.12-slim
# pg_dump/pg_restore matching PasarGuard's PostgreSQL 17, from the PostgreSQL apt repository.
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && install -d /usr/share/postgresql-common/pgdg \
    && curl -fsSL -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc https://www.postgresql.org/media/keys/ACCC4CF8.asc \
    && . /etc/os-release \
    && echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt ${VERSION_CODENAME}-pgdg main" > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update && apt-get install -y --no-install-recommends postgresql-client-17 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=goacme/lego:v5.5.2 /lego /usr/local/bin/lego
WORKDIR /app
COPY panel/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY panel/zarrin ./zarrin
COPY --from=web /web/dist ./web
ENV PYTHONUNBUFFERED=1
CMD ["python", "-m", "zarrin.main"]
