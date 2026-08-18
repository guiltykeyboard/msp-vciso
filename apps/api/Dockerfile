FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/apps/api

WORKDIR /app

COPY requirements.txt requirements-dev.txt ./
RUN python -m pip install --no-cache-dir --requirement requirements.txt --requirement requirements-dev.txt

COPY alembic.ini pyproject.toml ./
COPY apps/api ./apps/api
COPY api ./api
COPY db ./db
COPY tests ./tests
COPY tools ./tools

RUN useradd --create-home --uid 10001 watchtower \
    && chown -R watchtower:watchtower /app

USER watchtower

EXPOSE 8000

CMD ["uvicorn", "watchtower_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
