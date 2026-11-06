FROM python:3.13-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
RUN useradd --system --uid 10001 --home /app cage
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY --chown=cage:cage app ./app
COPY --chown=cage:cage migrations ./migrations
COPY --chown=cage:cage alembic.ini .
# Device CA, command-signing and OIDC keys live here; mount a persistent, backed-up volume (see docker-compose.yml).
RUN mkdir -p /app/var && chown cage:cage /app/var && chmod 700 /app/var
USER cage
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*", "--no-server-header"]
