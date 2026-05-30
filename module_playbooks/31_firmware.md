# Firmware / Embedded Security — Master Reference (`firmware_ruff`)

**100% Full Industry Standard catalogue** — aligned with OWASP Embedded Security + NIST SP 800-193 (Platform Firmware Resiliency) + FACT toolkit + Binwalk methodology + 2024–2026 industry additions.

8 sections, 75 techniques. ✅ auto · 👤 manual · ⭐ NEW 2024+

---

## Summary

| § | Section | Techniques | Auto | Manual |
|---|---|---|---|---|
| 1 | Firmware Acquisition | 10 | 6 | 4 |
| 2 | Static Firmware Analysis | 12 | 11 | 1 |
| 3 | Filesystem Extraction | 8 | 8 | 0 |
| 4 | Binary Reverse Engineering | 10 | 6 | 4 |
| 5 | Bootloader / Secure Boot | 8 | 5 | 3 |
| 6 | UART / JTAG / SWD Hardware | 10 | 3 | 7 |
| 7 | Side-channel / Fault Injection ⭐ | 8 | 2 | 6 |
| 8 | Modern Firmware Surfaces (UEFI, BMC, TPM) ⭐ | 10 | 6 | 4 |
| **TOTAL** | | **76** | **47** | **29** |

---

## §1 — Firmware Acquisition
1 Vendor download (FTP/HTTPS) · 2 OTA update interception · 3 ⭐ Firmware blob extraction via UART · 4 SPI flash chip dump (BusPirate) 👤 · 5 eMMC / NAND chip-off 👤 · 6 In-circuit JTAG / SWD dump 👤 · 7 Bootloader recovery mode dump · 8 ⭐ Cloud firmware mirror enum (s3 bucket) · 9 Manual creative acquisition 👤 · 10 ⭐ Manual SDR-based OTA capture 👤

## §2 — Static Firmware Analysis
11 binwalk signature scan · 12 binwalk extract (-e) · 13 ⭐ unblob (modern binwalk alternative) · 14 fmk / firmware-mod-kit · 15 FACT (Firmware Analysis and Comparison Toolkit) · 16 EMBA enterprise scan · 17 firmwalker grep · 18 ⭐ Trivy filesystem scan · 19 entropy analysis (high → encrypted/compressed) · 20 strings + grep secrets/URLs · 21 ⭐ Pulsar firmware analysis · 22 Manual creative analysis 👤

## §3 — Filesystem Extraction
23 squashfs-tools extraction · 24 jefferson JFFS2 extraction · 25 cramfs extraction · 26 yaffs2 extraction · 27 cpio extraction · 28 mtdtools NAND extraction · 29 UBIFS extraction · 30 ⭐ ubi_reader

## §4 — Binary Reverse Engineering
31 Ghidra free decompiler · 32 IDA Pro · 33 radare2 / r2 · 34 Binary Ninja · 35 ⭐ AI-assisted RE (G3PT, Reveng.ai) · 36 ELF section analysis · 37 PE / Mach-O on embedded · 38 Manual ARM / MIPS / PowerPC RE 👤 · 39 Manual creative binary chain 👤 · 40 Manual firmware diffing (BinDiff) 👤

## §5 — Bootloader / Secure Boot
41 U-Boot version + CVE check · 42 GRUB / EFI boot enum · 43 ⭐ U-Boot env tamper · 44 Bootloader unlock procedure · 45 Secure Boot chain audit · 46 ⭐ Manual rollback attack on signed bootloader 👤 · 47 ⭐ Manual TOCTOU on secure boot verification 👤 · 48 Manual creative bootloader exploit 👤

## §6 — UART / JTAG / SWD Hardware
49 UART pin discovery (PCBite / oscilloscope) 👤 · 50 UART connection (3.3V / 5V baud detect) 👤 · 51 ⭐ JTAGulator pin discovery · 52 OpenOCD JTAG/SWD interface · 53 BusPirate UART/SPI · 54 ⭐ Glasgow Interface Explorer · 55 Manual JTAG protocol RE 👤 · 56 Manual SWD chain 👤 · 57 Manual UART shell privesc 👤 · 58 Manual creative hardware chain 👤

## §7 — Side-channel / Fault Injection ⭐ NEW
59 ⭐ ChipWhisperer power analysis · 60 ⭐ ChipWhisperer voltage glitch · 61 ⭐ Clock glitch injection 👤 · 62 ⭐ EM (electromagnetic) injection 👤 · 63 ⭐ Laser fault injection 👤 · 64 ⭐ Power-analysis key recovery 👤 · 65 ⭐ Manual creative side-channel 👤 · 66 ⭐ Manual creative fault chain 👤

## §8 — Modern Firmware Surfaces (UEFI, BMC, TPM) ⭐ NEW
67 ⭐ CHIPSEC UEFI security · 68 ⭐ UEFI firmware extraction (UEFITool) · 69 ⭐ BIOS / UEFI vulnerability check · 70 ⭐ BMC / iLO / iDRAC vuln scan · 71 ⭐ TPM 2.0 attestation audit · 72 ⭐ TPM PCR manipulation 👤 · 73 ⭐ Intel Boot Guard audit · 74 ⭐ AMD PSP audit · 75 ⭐ Manual creative platform-firmware chain 👤 · 76 ⭐ Manual creative TEE/SGX bypass 👤

---

## Compliance Mapping
- **NIST SP 800-193 (Platform Firmware Resiliency)** · **NIST SP 800-147 (BIOS Protection)** · **OWASP Embedded Application Security** · **UL 2900 (Network-connectable products)** · **ETSI EN 303 645 (Consumer IoT)** · **EU CRA (firmware obligations)**

## VulnusLab Status
- 🔴 MISSING (module #31 in inventory) · Priority: 🟢 P3 (hardware customers only)
- Coverage: 0%

## References
- binwalk: https://github.com/ReFirmLabs/binwalk · unblob: https://github.com/onekey-sec/unblob · FACT: https://github.com/fkie-cad/FACT_core · EMBA: https://github.com/e-m-b-a/emba · firmwalker: https://github.com/craigz28/firmwalker · CHIPSEC: https://github.com/chipsec/chipsec · OpenOCD: https://openocd.org/ · ChipWhisperer: https://www.newae.com/chipwhisperer · JTAGulator: http://www.grandideastudio.com/jtagulator/
