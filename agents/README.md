# VulnusLab on-site Wi-Fi capture agent

Wi-Fi attacks split into two halves:

- **Live RF (on-site):** monitor mode, scanning, handshake/PMKID capture. Needs
  a monitor-mode Wi-Fi adapter physically near the target access point. This
  **cannot** run on the hosted cloud engine, which has no radio.
- **Offline analysis (hosted):** cracking the captured handshake/PMKID against a
  wordlist and reporting. Pure compute, runs on the VulnusLab engine.

`wifi_capture_agent.py` is the on-site half. You run it on a laptop with a
wireless adapter during an authorized engagement; it captures and uploads the
result to the engine's `/api/wireless/handshake_crack/upload`. The engine then
does the offline crack via `/api/wireless/handshake_crack`.

## Authorization

Capturing traffic from a network you do not own or lack written permission to
test is illegal. The agent refuses to run without `--authorize`, and records
the acknowledgment with the upload. Use it only within an authorized scope.

## Requirements

- Root (monitor mode and raw capture need it).
- `aircrack-ng` suite (`airmon-ng`, `airodump-ng`, `aireplay-ng`) for the
  handshake path, or `hcxdumptool` for the PMKID path.
- Python 3.8+ (standard library only — no pip installs).

## Usage

Handshake capture, auto-selecting the target by SSID, forcing a reconnect:

```
sudo python3 wifi_capture_agent.py \
  --interface wlan0 \
  --server https://vulnuslab.com \
  --token "$VL_TOKEN" \
  --authorize "ENG-1423 / client: ACME, owner-approved" \
  --essid "ACME-Corp" \
  --deauth 5 \
  --duration 60
```

PMKID capture (no connected client needed) against a known BSSID:

```
sudo python3 wifi_capture_agent.py \
  --interface wlan0 --pmkid \
  --server https://vulnuslab.com --token "$VL_TOKEN" \
  --authorize "ENG-1423 owner-approved" \
  --bssid AA:BB:CC:DD:EE:FF --duration 45
```

Capture only, no upload (inspect locally first):

```
sudo python3 wifi_capture_agent.py --interface wlan0 \
  --authorize "lab self-test" --bssid AA:BB:CC:DD:EE:FF --channel 6 --no-upload
```

## What the engine does with the upload

1. Stores the capture under the server's `wireless_captures` upload dir.
2. On `POST /api/wireless/handshake_crack` with the returned `capture_path`,
   runs `aircrack-ng` (handshake) or `hashcat -m 22000` (PMKID) against a
   wordlist with a wall-clock cap.
3. Reports a CRITICAL finding if the passphrase is recovered (weak PSK), or an
   INFO result if not — never a false "secure" (absence of a crack only means
   the key was not in the wordlist).
