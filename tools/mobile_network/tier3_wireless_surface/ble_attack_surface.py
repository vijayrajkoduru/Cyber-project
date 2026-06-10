"""ble_attack_surface — detect BLE (Bluetooth Low Energy) usage so the
customer knows whether to engage a BLE pentest. Flags: BLUETOOTH_SCAN,
BLUETOOTH_CONNECT, BLUETOOTH_ADVERTISE perms, BluetoothLeScanner API,
GattCallback, custom GATT services / characteristics."""
from __future__ import annotations
from pathlib import Path
from xml.etree import ElementTree as ET

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.ble_attack_surface_findings import BLE_ATTACK_SURFACE_FINDING_RULES

router = APIRouter()

NS = {"a": "http://schemas.android.com/apk/res/android"}
BLE_PERMS = (
    "android.permission.BLUETOOTH",
    "android.permission.BLUETOOTH_ADMIN",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_ADVERTISE",
    "android.permission.ACCESS_FINE_LOCATION",   # required for BLE scan pre-API 31
)
BLE_API_MARKERS = (
    "BluetoothAdapter", "BluetoothLeScanner", "BluetoothGatt",
    "BluetoothGattCallback", "BluetoothGattCharacteristic",
    "BluetoothGattService", "BluetoothDevice;->connectGatt",
    "ScanCallback", "ScanFilter", "ScanResult",
    "AdvertisingSet", "BluetoothLeAdvertiser",
)
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["ble_attack_surface_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["ble_attack_surface_error"] = str(e)
        return

    perms_found = []
    manifest = unpacked / "AndroidManifest.xml"
    if manifest.is_file():
        try:
            root = ET.parse(str(manifest)).getroot()
            for p in root.findall("uses-permission"):
                name = p.get(f"{{{NS['a']}}}name", "")
                if name in BLE_PERMS:
                    perms_found.append(name)
        except ET.ParseError:
            pass

    api_hits = {}
    files_scanned = 0
    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1
        for marker in BLE_API_MARKERS:
            if marker in txt:
                api_hits.setdefault(marker, [])
                if p.name not in api_hits[marker] and len(api_hits[marker]) < 5:
                    api_hits[marker].append(p.name)
                break

    ctx.state["ble_permissions"] = perms_found
    ctx.state["ble_api_hits"] = api_hits
    ctx.state["files_scanned"] = files_scanned
    ctx.state["ble_attack_surface_total"] = (1 if perms_found else 0) + (1 if api_hits else 0)
    ctx.source(f"manifest + {files_scanned} smali files")


INTEL_FIELDS = [
    ("BLE permissions requested", "ble_permissions"),
    ("BLE API usage", "ble_api_hits"),
]


@router.post("/api/mobile_network/ble_attack_surface")
async def mobile_network_ble_attack_surface(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="ble_attack_surface",
        gather_func=gather,
        finding_rules=BLE_ATTACK_SURFACE_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
