FROM python:3.11-alpine

RUN pip install --no-cache-dir flask==3.0.0

WORKDIR /app
COPY app.py /app/app.py

EXPOSE 5000

# python:3.11-alpine doesn't include wget/curl, so use Python stdlib
# urllib for the healthcheck (Python is guaranteed present).
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://localhost:5000/health',timeout=2).read() or sys.exit(1)" || exit 1

CMD ["python", "/app/app.py"]
