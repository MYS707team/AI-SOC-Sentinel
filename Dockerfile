FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SOC_DATA_DIR=/data
WORKDIR /opt/ai-soc
COPY requirements.txt requirements.lock.txt ./
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home soc && mkdir /data && chown soc:soc /data
COPY --chown=soc:soc app ./app
COPY --chown=soc:soc web ./web
USER soc
EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/healthz',timeout=3)"
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8765", "--workers", "1", "--no-proxy-headers"]
