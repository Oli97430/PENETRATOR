# ── Stage 1: Install dependencies ──
FROM python:3.12-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: Runtime ──
FROM python:3.12-slim

WORKDIR /app

COPY --from=builder /install /usr/local

COPY gui/ gui/
COPY core/ core/
COPY modules/ modules/
COPY penetrator_api.py .
COPY penetrator.py .
COPY penetrator_cli.py .
COPY .env.example .

RUN useradd --create-home appuser \
    && mkdir -p data/reports \
    && chown -R appuser:appuser data
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "penetrator_api:app", "--host", "0.0.0.0", "--port", "8000"]
