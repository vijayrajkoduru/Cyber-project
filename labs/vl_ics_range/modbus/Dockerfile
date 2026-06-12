FROM python:3.12-slim
RUN pip install --no-cache-dir "pymodbus>=3.6,<4"
COPY server.py /server.py
EXPOSE 502
CMD ["python", "/server.py"]
