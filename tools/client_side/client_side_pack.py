"""§9 Client-Side Attacks — 56 endpoints per 09_client_side.md.
7 sections: BeEF hooks, Office macros, HTA, LNK, browser exploits,
SE payload delivery, modern browser surface.
"""
from tools._pack_common import make_advisory_router

TECHNIQUES = [
    # §1 Browser Hooks / BeEF (8)
    ("beef_hook_xss_delivery", "BeEF hook delivery via XSS.", "HIGH", "7.5"),
    ("beef_browser_info_collect", "BeEF browser-info collection.", "MEDIUM", "5.5"),
    ("beef_clipboard_hijack", "BeEF clipboard hijack.", "MEDIUM", "5.5"),
    ("beef_webcam_mic_prompt", "BeEF webcam/mic access prompt.", "HIGH", "7.0"),
    ("beef_tabnabbing", "BeEF tabnabbing.", "MEDIUM", "5.5"),
    ("beef_internal_scan_pivot", "BeEF browser-pivoted internal scan.", "HIGH", "7.5"),
    ("beef_social_eng_modules", "BeEF social-engineering modules.", "MEDIUM", "5.5"),
    ("custom_js_keylogger", "Custom JS keylogger.", "HIGH", "7.5"),
    # §2 Document / Office Macros (10)
    ("macro_pack_vba_gen", "macro_pack VBA generation.", "HIGH", "7.5"),
    ("vba_powershell_stager", "VBA → PowerShell stager.", "HIGH", "7.5"),
    ("excel_4_xlm_macro", "Excel 4.0 macro (XLM) abuse.", "HIGH", "7.5"),
    ("word_remote_template_injection", "Word remote-template injection.", "HIGH", "7.5"),
    ("dde_field_abuse_legacy", "DDE field abuse (legacy).", "MEDIUM", "5.5"),
    ("ole_object_embedding", "OLE object embedding.", "HIGH", "7.0"),
    ("pdf_javascript_embed", "PDF JavaScript embed.", "HIGH", "7.0"),
    ("onenote_one_attack_chain", "⭐ OneNote .one file attack chain.", "HIGH", "8.0"),
    ("iso_img_container_delivery", "⭐ ISO/IMG container delivery.", "HIGH", "8.0"),
    ("outlook_custom_form_attack", "⭐ Outlook custom form attack.", "HIGH", "7.5"),
    # §3 HTA (5)
    ("hta_payload_msfvenom", "HTA payload generation via msfvenom.", "HIGH", "7.5"),
    ("mshta_url_exec", "mshta.exe execution via URL.", "HIGH", "7.5"),
    ("hta_in_iframe", "HTA in iframe.", "HIGH", "7.0"),
    ("hta_powershell_stager", "HTA → PowerShell stager chain.", "HIGH", "7.5"),
    ("hta_amsi_bypass", "⭐ HTA AMSI bypass.", "HIGH", "8.0"),
    # §4 LNK / Shortcut Abuse (7)
    ("lnk_payload_generation", "LNK payload generation.", "HIGH", "7.5"),
    ("lnk_icon_spoofing", "LNK icon spoofing.", "HIGH", "7.0"),
    ("lnk_powershell_stager", "LNK + PowerShell stager.", "HIGH", "7.5"),
    ("lnk_in_archive_zip", "LNK in archive (.zip social-eng delivery).", "HIGH", "7.5"),
    ("lnk_vbs_js_chain", "⭐ LNK + .vbs/.js chain (2024+).", "HIGH", "7.5"),
    ("mark_of_the_web_bypass", "⭐ Mark-of-the-Web bypass.", "HIGH", "8.0"),
    ("url_file_abuse", "URL file (.url) abuse.", "MEDIUM", "5.5"),
    # §5 Browser-side Exploits (8)
    ("firefox_edge_safari_cve", "Firefox/Edge/Safari CVE probe.", "HIGH", "7.5"),
    ("drive_by_download", "Drive-by download.", "HIGH", "7.0"),
    ("clickjacking_probe", "Clickjacking probe.", "MEDIUM", "5.5"),
    ("cross_origin_info_leak", "Cross-origin info leak.", "HIGH", "7.0"),
    ("xs_leaks_research", "⭐ XS-Leaks (cross-site leaks) research.", "MEDIUM", "5.5"),
    ("browser_extension_cve", "Browser plugin/extension CVE probe.", "HIGH", "7.0"),
    ("malicious_iframe_redress", "Malicious iframe + UI redress.", "MEDIUM", "5.5"),
    ("postmessage_origin_validation", "postMessage origin validation audit.", "MEDIUM", "5.5"),
    # §6 SE Payload Delivery (11)
    ("phishing_attachment_macro", "Phishing attachment (Office macro).", "HIGH", "7.5"),
    ("phishing_attachment_hta", "Phishing attachment (HTA).", "HIGH", "7.5"),
    ("phishing_attachment_lnk", "Phishing attachment (LNK).", "HIGH", "7.5"),
    ("phishing_attachment_iso", "⭐ Phishing attachment (ISO/IMG).", "HIGH", "8.0"),
    ("phishing_link_clone_site", "Phishing link + cloned site.", "HIGH", "7.5"),
    ("evilginx2_phish_payload", "⭐ EvilGinx2 + payload delivery.", "CRITICAL", "9.0"),
    ("usb_hid_payload_rubber_ducky", "USB HID payload (Rubber Ducky).", "MEDIUM", "5.5"),
    ("usb_bashbunny_payload", "USB Bash Bunny payload.", "MEDIUM", "5.5"),
    ("usb_malicious_image_iso", "USB malicious image/ISO.", "MEDIUM", "5.5"),
    ("dropper_signed_binary", "Signed-binary dropper (LOLBin abuse).", "HIGH", "7.5"),
    ("html_smuggling", "⭐ HTML smuggling.", "HIGH", "8.0"),
    # §7 Modern Browser Surface (7) ⭐
    ("manifest_v3_extension_abuse", "⭐ Manifest v3 extension abuse.", "HIGH", "7.5"),
    ("webview_android_ios_xss", "⭐ WebView XSS (Android/iOS).", "HIGH", "7.5"),
    ("webusb_webhid_abuse", "⭐ WebUSB/WebHID abuse.", "MEDIUM", "5.5"),
    ("webauthn_phishing_resistant_audit", "⭐ WebAuthn phishing-resistant audit.", "MEDIUM", "5.5"),
    ("service_worker_persistence", "⭐ Service Worker persistence.", "HIGH", "7.0"),
    ("local_storage_token_steal", "⭐ Local storage token steal.", "HIGH", "7.0"),
    ("indexeddb_data_extract", "⭐ IndexedDB data extract.", "MEDIUM", "5.5"),
]

router = make_advisory_router("client_side", TECHNIQUES,
    playbook_ref="See module_playbooks/09_client_side.md.")


def register(app):
    app.include_router(router)
