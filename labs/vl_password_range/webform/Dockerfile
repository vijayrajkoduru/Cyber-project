FROM python:3.11-alpine

RUN pip install --no-cache-dir flask==3.0.0

WORKDIR /app
COPY app.py /app/app.py

EXPOSE 5000

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://localhost:5000/health || exit 1

CMD ["python", "/app/app.py"]
