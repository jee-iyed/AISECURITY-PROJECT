FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Unprivileged runtime user; application code stays root-owned (read-only to it).
RUN useradd --create-home --uid 10001 gateway
COPY app ./app
RUN mkdir -p data logs && chown gateway:gateway data logs
USER gateway
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
