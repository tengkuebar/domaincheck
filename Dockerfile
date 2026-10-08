FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY pyproject.toml ./
COPY app ./app
RUN pip install --no-cache-dir . && useradd --system --no-create-home appuser
USER appuser
EXPOSE 8000
CMD ["uvicorn", "app.main:create_app", "--factory", "--no-access-log", "--host", "0.0.0.0", "--port", "8000"]
