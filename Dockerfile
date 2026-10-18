FROM python:3.11-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY frontend ./frontend
COPY scripts ./scripts
COPY data ./data
COPY tests ./tests
COPY pytest.ini .
# evaluation/ (ground truth) is copied only so `scripts.evaluate` can run in the container;
# the engine refuses to read it (app.config.assert_engine_readable).
COPY evaluation ./evaluation
RUN useradd -r -u 10001 app && chown -R app /app
USER app
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=5 CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"
CMD ["uvicorn", "app.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
