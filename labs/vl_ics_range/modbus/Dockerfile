FROM python:3.12-slim
# Pin to 3.6.x — pymodbus 3.7+ renamed ModbusSlaveContext (server.py uses the
# classic API: ModbusSlaveContext / ModbusServerContext(slaves=) / StartTcpServer).
RUN pip install --no-cache-dir "pymodbus==3.6.9"
COPY server.py /server.py
EXPOSE 502
CMD ["python", "/server.py"]
