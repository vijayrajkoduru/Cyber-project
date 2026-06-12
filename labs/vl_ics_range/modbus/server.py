"""VL ICS Range - Modbus/TCP simulator (unauthenticated, port 502).

A deliberately-exposed Modbus/TCP server for the IoT/OT module and
vuln tier15_wireless_iot. Modbus has no authentication by design, so an
exposed server on 502 is the classic ICS/OT finding: any client can read
and WRITE coils/registers (i.e. flip a PLC output) with no credentials.

Populated with 100 coils / discrete inputs / holding registers / input
registers so read-* and write-* probes return data instead of errors.
"""
from pymodbus.server import StartTcpServer
from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusSlaveContext,
    ModbusServerContext,
)
from pymodbus.device import ModbusDeviceIdentification

store = ModbusSlaveContext(
    di=ModbusSequentialDataBlock(0, [1] * 100),
    co=ModbusSequentialDataBlock(0, [1] * 100),
    hr=ModbusSequentialDataBlock(0, list(range(100))),
    ir=ModbusSequentialDataBlock(0, list(range(100))),
)
context = ModbusServerContext(slaves=store, single=True)

ident = ModbusDeviceIdentification()
ident.VendorName = "VulnusLab"
ident.ProductCode = "VL-ICS"
ident.VendorUrl = "https://vulnuslab.com"
ident.ProductName = "VL Modbus Range"
ident.ModelName = "VL-PLC-1"
ident.MajorMinorRevision = "1.0"

if __name__ == "__main__":
    print("VL Modbus/TCP simulator listening on 0.0.0.0:502", flush=True)
    StartTcpServer(context=context, identity=ident, address=("0.0.0.0", 502))
