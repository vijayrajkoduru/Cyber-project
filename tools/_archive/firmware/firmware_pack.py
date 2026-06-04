"""§31 Firmware/Embedded — 47 endpoints per 31_firmware.md."""
from tools._pack_common import make_advisory_router

T = [
    # §1 Firmware Acquisition (6)
    ("vendor_download_audit", "Vendor download audit.", "INFO", "0.0"),
    ("ota_update_capture", "OTA update capture.", "MEDIUM", "5.5"),
    ("spi_flash_dump", "SPI flash dump (chip-off).", "MEDIUM", "5.5"),
    ("emmc_dump_advisory", "eMMC dump advisory.", "MEDIUM", "5.5"),
    ("uart_dump", "UART firmware dump.", "MEDIUM", "5.5"),
    ("jtag_dump", "JTAG firmware dump.", "MEDIUM", "5.5"),
    # §2 Static Firmware Analysis (11)
    ("binwalk_extract", "binwalk extract.", "INFO", "0.0"),
    ("firmware_hex_analysis", "Hex/strings analysis.", "INFO", "0.0"),
    ("entropy_analysis", "Entropy analysis (encrypted regions).", "INFO", "0.0"),
    ("firmware_yara_scan", "YARA scan.", "MEDIUM", "5.5"),
    ("strings_secrets_grep", "strings → secrets grep.", "HIGH", "7.5"),
    ("hardcoded_creds_audit", "Hardcoded creds audit.", "HIGH", "8.0"),
    ("hardcoded_keys_audit", "Hardcoded keys audit.", "HIGH", "8.0"),
    ("firmware_signing_audit", "Firmware signing audit.", "MEDIUM", "5.5"),
    ("checkmate_firmware", "checkmate firmware audit.", "MEDIUM", "5.5"),
    ("firmwalker_audit", "firmwalker audit.", "MEDIUM", "5.5"),
    ("manual_firmware_static_review", "Manual static review.", "INFO", "0.0"),
    # §3 Filesystem Extraction (8)
    ("squashfs_extract", "squashfs extract.", "INFO", "0.0"),
    ("cpio_extract", "cpio extract.", "INFO", "0.0"),
    ("jffs2_extract", "JFFS2 extract.", "INFO", "0.0"),
    ("ubi_extract", "UBI extract.", "INFO", "0.0"),
    ("yaffs2_extract", "YAFFS2 extract.", "INFO", "0.0"),
    ("ext4_extract", "ext4 extract.", "INFO", "0.0"),
    ("fat_extract", "FAT extract.", "INFO", "0.0"),
    ("nand_dump_extract", "NAND dump extract.", "INFO", "0.0"),
    # §4 Binary Reverse Engineering (6)
    ("ghidra_static_analysis", "Ghidra static analysis.", "MEDIUM", "5.5"),
    ("ida_pro_analysis", "IDA Pro analysis.", "MEDIUM", "5.5"),
    ("radare2_r2_analysis", "radare2 / r2 analysis.", "MEDIUM", "5.5"),
    ("binary_ninja_analysis", "Binary Ninja analysis.", "MEDIUM", "5.5"),
    ("emulator_qemu_run", "QEMU run firmware.", "MEDIUM", "5.5"),
    ("manual_binary_review", "Manual binary review.", "INFO", "0.0"),
    # §5 Bootloader / Secure Boot (5)
    ("uboot_audit", "U-Boot audit.", "MEDIUM", "5.5"),
    ("uboot_env_audit", "U-Boot env audit.", "MEDIUM", "5.5"),
    ("secure_boot_audit", "Secure boot audit.", "HIGH", "7.5"),
    ("verified_boot_audit", "Verified boot (AVB) audit.", "MEDIUM", "5.5"),
    ("manual_bootloader_review", "Manual bootloader review.", "INFO", "0.0"),
    # §6 UART/JTAG/SWD (3)
    ("uart_probe_advisory", "UART probe advisory.", "MEDIUM", "5.5"),
    ("jtag_probe_advisory", "JTAG probe advisory.", "MEDIUM", "5.5"),
    ("swd_probe_advisory", "SWD probe advisory.", "MEDIUM", "5.5"),
    # §7 Side-channel / Fault Injection (2)
    ("chipwhisperer_advisory", "ChipWhisperer side-channel advisory.", "MEDIUM", "5.5"),
    ("emfi_voltage_glitching", "Voltage glitching advisory.", "MEDIUM", "5.5"),
    # §8 Modern Firmware Surfaces (6)
    ("uefi_audit", "UEFI audit.", "HIGH", "7.5"),
    ("uefi_bootkit_check", "UEFI bootkit check.", "CRITICAL", "9.0"),
    ("bmc_ipmi_audit", "BMC/IPMI audit.", "HIGH", "8.0"),
    ("tpm_audit", "TPM 2.0 audit.", "MEDIUM", "5.5"),
    ("secure_enclave_audit", "Secure enclave audit.", "MEDIUM", "5.5"),
    ("manual_modern_firmware_review", "Manual modern firmware review.", "INFO", "0.0"),
]

router = make_advisory_router("firmware", T,
    playbook_ref="See module_playbooks/31_firmware.md.")


def register(app):
    app.include_router(router)
