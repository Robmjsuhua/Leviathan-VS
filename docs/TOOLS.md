# LEVIATHAN VS — Tool Reference (v14.1.0)

> Auto-generated tool catalog for all 33 MCP servers and 460+ tools.
> Last updated: 2026-02-25

---

## Overview

| Metric           | Count                                                          |
| ---------------- | -------------------------------------------------------------- |
| **MCP Servers**  | 33 (19 custom + 14 third-party)                                |
| **Custom Tools** | 464                                                            |
| **Categories**   | Security, Reverse Engineering, Network, Emulators, Translation |

---

## Table of Contents

- [Core Servers](#core-servers)
  - [Leviathan (Translation Engine)](#leviathan-translation-engine)
  - [HTTP Toolkit](#http-toolkit)
- [Security & Pentesting](#security--pentesting)
  - [Frida (Dynamic Instrumentation)](#frida-dynamic-instrumentation)
  - [Objection (Runtime Exploration)](#objection-runtime-exploration)
  - [Nuclei + Scanner Suite](#nuclei--scanner-suite)
  - [Hashcat (Password Cracking)](#hashcat-password-cracking)
  - [BurpSuite (Web Security)](#burpsuite-web-security)
- [Reverse Engineering](#reverse-engineering)
  - [JADX (Java Decompiler)](#jadx-java-decompiler)
  - [Ghidra (Binary Analysis)](#ghidra-binary-analysis)
  - [Radare2 (Binary Analysis)](#radare2-binary-analysis)
  - [Androguard (APK Analysis)](#androguard-apk-analysis)
  - [APKTool (APK Build/Patch)](#apktool-apk-buildpatch)
- [Network & Traffic](#network--traffic)
  - [Scapy (Packet Crafting)](#scapy-packet-crafting)
  - [Wireshark (Packet Analysis)](#wireshark-packet-analysis)
  - [MITMProxy (HTTP Interception)](#mitmproxy-http-interception)
- [Android Emulators](#android-emulators)
  - [LDPlayer (Mega Server)](#ldplayer-mega-server)
  - [BlueStacks](#bluestacks)
  - [MEmu](#memu)
  - [Nox](#nox)
  - [ADB (Android Debug Bridge)](#adb-android-debug-bridge)
- [Third-Party Servers](#third-party-servers)

---

## Core Servers

### Leviathan (Translation Engine)
**Server:** `leviathan` · **Path:** `core/mcp_server.py` · **Tools:** 7

| Tool             | Description                                                             |
| ---------------- | ----------------------------------------------------------------------- |
| `encode`         | Sanitize text — replace sensitive terms with neutral graph-theory terms |
| `decode`         | Restore original terms from sanitized text                              |
| `check`          | Check if text contains sensitive terms                                  |
| `find_terms`     | Find and list all sensitive terms with positions                        |
| `reload_rules`   | Reload translation rules from config.json                               |
| `get_rules`      | Return all loaded translation rules (with optional category filter)     |
| `translate_file` | Translate an entire file (with automatic backup)                        |

### HTTP Toolkit
**Server:** N/A (CLI tool) · **Path:** `core/http_toolkit.py` · **Modes:** 5

| Mode      | Description                                                                  |
| --------- | ---------------------------------------------------------------------------- |
| `scan`    | Full HTTP endpoint scan (GET, POST, PUT, PATCH; DELETE requires SAFE_MODE=0) |
| `request` | Single HTTP request with full control                                        |
| `fuzz`    | Parameter fuzzing with wordlists                                             |
| `compare` | Compare two API endpoint responses                                           |
| `headers` | Analyze HTTP security headers                                                |

---

## Security & Pentesting

### Frida (Dynamic Instrumentation)
**Server:** `frida-standalone` · **Path:** `core/frida_mcp/mcp_frida.py` · **Tools:** 28

| Tool                      | Description                                    |
| ------------------------- | ---------------------------------------------- |
| `frida_list_devices`      | List available Frida devices                   |
| `frida_list_processes`    | List running processes on device               |
| `frida_list_apps`         | List installed applications                    |
| `frida_inject_script`     | Inject JavaScript into target process          |
| `frida_hook_java`         | Hook Java method (auto-generates Frida script) |
| `frida_hook_native`       | Hook native function (auto-generates script)   |
| `frida_memory_scan`       | Scan process memory for pattern                |
| `frida_dump_classes`      | Dump all loaded Java classes                   |
| `frida_dump_methods`      | Dump methods of a specific Java class          |
| `frida_heap_search`       | Search Java heap for object instances          |
| `frida_bypass_ssl`        | Inject SSL pinning bypass script               |
| `frida_bypass_root`       | Inject root detection bypass                   |
| `frida_bypass_emulator`   | Inject emulator detection bypass               |
| `frida_bypass_frida`      | Inject Frida detection bypass                  |
| `frida_dump_module`       | Dump native module information                 |
| `frida_enumerate_exports` | List exports of a native module                |
| `frida_enumerate_imports` | List imports of a native module                |
| `frida_intercept_network` | Hook send/recv for traffic interception        |
| `frida_xxtea_extract`     | Auto-extract XXTEA key from Cocos2d-x games    |
| `frida_generate_script`   | Generate predefined Frida scripts              |
| `frida_trace`             | Trace function calls matching a pattern        |
| `frida_memory_read`       | Read raw memory at address                     |
| `frida_memory_write`      | Write raw memory at address                    |
| `frida_backtrace`         | Get native backtrace from function             |
| `frida_stalker_trace`     | CPU instruction trace with Stalker engine      |
| `frida_spawn_gating`      | Control application spawn gating               |
| `frida_enumerate_modules` | List all loaded native modules                 |
| `frida_call_export`       | Call an exported native function directly      |

### Objection (Runtime Exploration)
**Server:** `objection` · **Path:** `core/objection/mcp_objection.py` · **Tools:** 20

| Tool                     | Description                         |
| ------------------------ | ----------------------------------- |
| `obj_explore`            | Start Objection exploration session |
| `obj_env`                | Get device environment info         |
| `obj_ssl_disable`        | Disable SSL pinning                 |
| `obj_root_disable`       | Disable root detection              |
| `obj_android_hooking`    | Hook Android methods                |
| `obj_android_intent`     | Launch Android intents              |
| `obj_android_keystore`   | Access Android keystore             |
| `obj_android_clipboard`  | Access clipboard contents           |
| `obj_memory_dump`        | Dump process memory                 |
| `obj_memory_search`      | Search memory for patterns          |
| `obj_sqlite`             | Query SQLite databases              |
| `obj_file_download`      | Download file from device           |
| `obj_file_upload`        | Upload file to device               |
| `obj_file_ls`            | List directory contents             |
| `obj_patchapk`           | Patch APK for Objection injection   |
| `obj_run_command`        | Run arbitrary Objection command     |
| `obj_android_activities` | List Android activities             |
| `obj_android_services`   | List Android services               |
| `obj_android_providers`  | List content providers              |
| `obj_android_receivers`  | List broadcast receivers            |

### Nuclei + Scanner Suite
**Server:** `nuclei` · **Path:** `core/nuclei/mcp_nuclei.py` · **Tools:** 17

| Tool               | Description                     |
| ------------------ | ------------------------------- |
| `nuclei_scan`      | Run Nuclei vulnerability scan   |
| `nuclei_templates` | List/search available templates |
| `nuclei_cve_scan`  | Scan for specific CVEs          |
| `nuclei_custom`    | Run with custom template        |
| `sqlmap_scan`      | SQLMap SQL injection scan       |
| `sqlmap_dump`      | Dump database via SQLi          |
| `sqlmap_tables`    | Enumerate database tables       |
| `sqlmap_dbs`       | Enumerate databases             |
| `nmap_scan`        | Network port scan               |
| `nmap_services`    | Service/version detection       |
| `nmap_vuln`        | Vulnerability script scan       |
| `dirb_scan`        | Directory brute-force           |
| `ffuf_fuzz`        | Web fuzzing with ffuf           |
| `nikto_scan`       | Web server vulnerability scan   |
| `whatweb_scan`     | Web technology fingerprinting   |
| `subfinder_enum`   | Subdomain enumeration           |
| `httpx_probe`      | HTTP endpoint probing           |

### Hashcat (Password Cracking)
**Server:** `hashcat` · **Path:** `core/hashcat/mcp_hashcat.py` · **Tools:** 12

| Tool                     | Description                       |
| ------------------------ | --------------------------------- |
| `hash_identify`          | Identify hash type                |
| `hash_crack`             | Run Hashcat cracking attack       |
| `hash_benchmark`         | Benchmark hash modes              |
| `hash_status`            | Check running session status      |
| `hash_show`              | Show cracked hashes from potfile  |
| `hash_generate_wordlist` | Generate wordlist from parameters |
| `hash_generate_rule`     | Generate Hashcat rule file        |
| `hash_combinator`        | Combinator attack (two wordlists) |
| `hash_mask_attack`       | Mask/brute-force attack           |
| `hash_john_crack`        | Run John the Ripper               |
| `hash_convert`           | Convert hash formats              |
| `hash_analyze_potfile`   | Analyze potfile statistics        |

### BurpSuite (Web Security)
**Server:** `burpsuite` · **Path:** `core/burpsuite/mcp_burpsuite.py` · **Tools:** 15

| Tool                    | Description                     |
| ----------------------- | ------------------------------- |
| `burp_scan`             | Active vulnerability scan       |
| `burp_spider`           | Spider/crawl target             |
| `burp_sitemap`          | Get site map contents           |
| `burp_issues`           | Get discovered issues           |
| `burp_proxy_history`    | Get proxy history               |
| `burp_intruder_attack`  | Run Intruder attack             |
| `burp_repeater_send`    | Send Repeater request           |
| `burp_decoder_encode`   | Encode data (URL, Base64, etc.) |
| `burp_decoder_decode`   | Decode data                     |
| `burp_target_scope`     | Manage target scope             |
| `burp_export_report`    | Export scan report              |
| `burp_proxy_intercept`  | Toggle proxy interception       |
| `burp_search_responses` | Search response content         |
| `burp_get_config`       | Get Burp configuration          |
| `burp_set_config`       | Update Burp configuration       |

---

## Reverse Engineering

### JADX (Java Decompiler)
**Server:** `jadx` · **Path:** `core/jadx/mcp_jadx.py` · **Tools:** 16

| Tool                   | Description                          |
| ---------------------- | ------------------------------------ |
| `jadx_decompile`       | Decompile APK/DEX to Java source     |
| `jadx_search_class`    | Search for a class by name           |
| `jadx_search_string`   | Search for string in decompiled code |
| `jadx_search_method`   | Search for method by name            |
| `jadx_list_classes`    | List all classes in APK              |
| `jadx_get_source`      | Get source code of specific class    |
| `jadx_get_manifest`    | Extract AndroidManifest.xml          |
| `jadx_get_permissions` | List declared permissions            |
| `jadx_get_activities`  | List all activities                  |
| `jadx_get_native_libs` | List native libraries                |
| `jadx_search_crypto`   | Find crypto-related code             |
| `jadx_search_urls`     | Find hardcoded URLs                  |
| `jadx_search_keys`     | Find API keys and secrets            |
| `jadx_get_resources`   | List application resources           |
| `jadx_export_smali`    | Export Smali code                    |
| `jadx_diff`            | Diff two APK versions                |

### Ghidra (Binary Analysis)
**Server:** `ghidra` · **Path:** `core/ghidra/mcp_ghidra.py` · **Tools:** 15

| Tool                      | Description                        |
| ------------------------- | ---------------------------------- |
| `ghidra_analyze`          | Analyze binary with Ghidra         |
| `ghidra_get_info`         | Get program info/metadata          |
| `ghidra_list_functions`   | List all functions                 |
| `ghidra_decompile`        | Decompile function to C pseudocode |
| `ghidra_search_strings`   | Search for strings in binary       |
| `ghidra_list_exports`     | List exported symbols              |
| `ghidra_list_imports`     | List imported symbols              |
| `ghidra_xrefs_to`         | Find cross-references to address   |
| `ghidra_get_sections`     | Get binary sections/segments       |
| `ghidra_run_script`       | Run Ghidra script                  |
| `ghidra_xrefs_from`       | Find cross-references from address |
| `ghidra_search_bytes`     | Search for byte pattern            |
| `ghidra_get_entry_points` | List entry points                  |
| `ghidra_list_classes`     | List detected classes              |
| `ghidra_get_data_types`   | List defined data types            |

### Radare2 (Binary Analysis)
**Server:** `radare2` · **Path:** `core/r2/mcp_r2.py` · **Tools:** 16

| Tool              | Description                   |
| ----------------- | ----------------------------- |
| `r2_analyze`      | Full binary analysis          |
| `r2_functions`    | List all functions            |
| `r2_disasm`       | Disassemble at address        |
| `r2_strings`      | Extract strings               |
| `r2_imports`      | List imports                  |
| `r2_exports`      | List exports                  |
| `r2_sections`     | List binary sections          |
| `r2_xrefs_to`     | Cross-references to address   |
| `r2_xrefs_from`   | Cross-references from address |
| `r2_hex_dump`     | Hex dump at address           |
| `r2_search`       | Search for bytes/strings      |
| `r2_info`         | Get binary information        |
| `r2_entry_points` | List entry points             |
| `r2_cmd`          | Run raw r2 command            |
| `r2_decompile`    | Decompile function (PDC)      |
| `r2_patch`        | Patch bytes at address        |

### Androguard (APK Analysis)
**Server:** `androguard` · **Path:** `core/androguard/mcp_androguard.py` · **Tools:** 15

| Tool                     | Description                 |
| ------------------------ | --------------------------- |
| `ag_analyze`             | Full APK analysis           |
| `ag_permissions`         | List permissions            |
| `ag_components`          | List app components         |
| `ag_strings`             | Extract strings             |
| `ag_certificate`         | Analyze signing certificate |
| `ag_classes`             | List all classes            |
| `ag_methods`             | List class methods          |
| `ag_api_calls`           | List API calls made         |
| `ag_native_libs`         | List native libraries       |
| `ag_xrefs`               | Cross-reference analysis    |
| `ag_search_code`         | Search in bytecode          |
| `ag_intent_filters`      | List intent filters         |
| `ag_compare`             | Compare two APK versions    |
| `ag_exported_components` | List exported components    |
| `ag_security_audit`      | Run security audit checks   |

### APKTool (APK Build/Patch)
**Server:** `apktool` · **Path:** `core/apktool/mcp_apktool.py` · **Tools:** 12

| Tool                         | Description                                 |
| ---------------------------- | ------------------------------------------- |
| `apktool_decode`             | Decode APK to Smali/resources               |
| `apktool_build`              | Rebuild APK from decoded files              |
| `apktool_sign`               | Sign APK with debug key                     |
| `apktool_zipalign`           | Optimize APK alignment                      |
| `apktool_patch_smali`        | Patch Smali bytecode                        |
| `apktool_patch_manifest`     | Modify AndroidManifest.xml                  |
| `apktool_search_smali`       | Search in Smali code                        |
| `apktool_list_smali_classes` | List Smali classes                          |
| `apktool_full_rebuild`       | Full decode → patch → build → sign pipeline |
| `apktool_inject_smali`       | Inject Smali code into class                |
| `apktool_diff`               | Diff two decoded APKs                       |
| `apktool_create_keystore`    | Create signing keystore                     |

---

## Network & Traffic

### Scapy (Packet Crafting)
**Server:** `scapy` · **Path:** `core/scapy/mcp_scapy.py` · **Tools:** 15

| Tool                  | Description                 |
| --------------------- | --------------------------- |
| `scapy_craft`         | Craft custom network packet |
| `scapy_send`          | Send crafted packet         |
| `scapy_sniff`         | Sniff network traffic       |
| `scapy_traceroute`    | Traceroute to host          |
| `scapy_arp_scan`      | ARP network discovery       |
| `scapy_port_scan`     | TCP SYN port scan           |
| `scapy_dns_query`     | DNS query                   |
| `scapy_ping`          | ICMP ping                   |
| `scapy_fuzz`          | Protocol fuzzing            |
| `scapy_read_pcap`     | Read PCAP file              |
| `scapy_write_pcap`    | Write packets to PCAP       |
| `scapy_dissect`       | Dissect packet layers       |
| `scapy_sr1`           | Send/receive single packet  |
| `scapy_tcp_handshake` | Perform TCP 3-way handshake |
| `scapy_fragment`      | Fragment packet             |

### Wireshark (Packet Analysis)
**Server:** `wireshark` · **Path:** `core/wireshark/mcp_wireshark.py` · **Tools:** 23

| Tool                     | Description                    |
| ------------------------ | ------------------------------ |
| `ws_interfaces`          | List capture interfaces        |
| `ws_capture`             | Start packet capture           |
| `ws_read`                | Read PCAP file                 |
| `ws_stats_endpoints`     | Endpoint statistics            |
| `ws_stats_conversations` | Conversation statistics        |
| `ws_stats_protocol`      | Protocol hierarchy             |
| `ws_stats_io`            | I/O statistics                 |
| `ws_follow_stream`       | Follow TCP/UDP stream          |
| `ws_extract_fields`      | Extract specific fields        |
| `ws_filter`              | Apply display filter           |
| `ws_decode_as`           | Decode as specific protocol    |
| `ws_export_objects`      | Export HTTP/SMB objects        |
| `ws_find_packets`        | Find packets matching criteria |
| `ws_dns_queries`         | Extract DNS queries            |
| `ws_http_requests`       | Extract HTTP requests          |
| `ws_tls_handshakes`      | Analyze TLS handshakes         |
| `ws_credentials`         | Find cleartext credentials     |
| `ws_expert_info`         | Get expert analysis info       |
| `ws_rtp_streams`         | Analyze RTP streams            |
| `ws_voip_calls`          | Detect VoIP calls              |
| `ws_wireless_stats`      | Wireless statistics            |
| `ws_geo_ip`              | GeoIP endpoint mapping         |
| `ws_packet_lengths`      | Packet length distribution     |

### MITMProxy (HTTP Interception)
**Server:** `mitmproxy` · **Path:** `core/mitmproxy/mcp_mitmproxy.py` · **Tools:** 14

| Tool                       | Description                      |
| -------------------------- | -------------------------------- |
| `mitm_start_proxy`         | Start MITM proxy instance        |
| `mitm_stop_proxy`          | Stop running proxy               |
| `mitm_dump_traffic`        | Dump captured traffic            |
| `mitm_read_flow`           | Read specific traffic flow       |
| `mitm_create_script`       | Create interception script       |
| `mitm_replay`              | Replay captured request          |
| `mitm_export_har`          | Export traffic as HAR            |
| `mitm_install_cert`        | Install CA certificate           |
| `mitm_extract_credentials` | Extract credentials from traffic |
| `mitm_modify_live`         | Modify live traffic              |
| `mitm_map_endpoints`       | Map discovered endpoints         |
| `mitm_diff_responses`      | Compare response versions        |
| `mitm_generate_curl`       | Generate curl command from flow  |
| `mitm_status`              | Get proxy status                 |

---

## Android Emulators

### LDPlayer (Mega Server)
**Server:** `ldplayer` · **Path:** `core/ldplayer/mcp_ldplayer.py` · **Tools:** 128

The LDPlayer server is the largest, combining ADB, Frida, bypass, and emulator management into a single orchestration server.

<details>
<summary>ADB Tools (41)</summary>

| Tool                    | Description                 |
| ----------------------- | --------------------------- |
| `adb_connect`           | Connect to emulator ADB     |
| `adb_disconnect`        | Disconnect ADB              |
| `adb_devices`           | List connected devices      |
| `adb_shell`             | Run shell command           |
| `adb_device_info`       | Get device info             |
| `adb_install_apk`       | Install APK                 |
| `adb_uninstall_app`     | Uninstall app               |
| `adb_list_packages`     | List installed packages     |
| `adb_start_app`         | Launch app by package       |
| `adb_force_stop`        | Force stop app              |
| `adb_clear_data`        | Clear app data              |
| `adb_pull_apk`          | Extract APK from device     |
| `adb_screenshot`        | Take screenshot             |
| `adb_screen_record`     | Record screen               |
| `adb_tap`               | Simulate tap at coordinates |
| `adb_swipe`             | Simulate swipe gesture      |
| `adb_input_text`        | Input text                  |
| `adb_key_event`         | Send key event              |
| `adb_push_file`         | Push file to device         |
| `adb_pull_file`         | Pull file from device       |
| `adb_logcat`            | Get logcat output           |
| `adb_set_proxy`         | Set network proxy           |
| `adb_port_forward`      | Set up port forwarding      |
| `adb_get_prop`          | Get system property         |
| `adb_set_prop`          | Set system property         |
| `adb_reboot`            | Reboot device               |
| `adb_battery_info`      | Get battery info            |
| `adb_memory_info`       | Get memory info             |
| `adb_cpu_info`          | Get CPU info                |
| `adb_disk_space`        | Get disk usage              |
| `adb_dumpsys`           | Run dumpsys for service     |
| `adb_list_services`     | List running services       |
| `adb_wifi_info`         | Get WiFi info               |
| `adb_ip_address`        | Get device IP               |
| `adb_airplane_mode`     | Toggle airplane mode        |
| `adb_install_cert`      | Install certificate         |
| `adb_open_url`          | Open URL in browser         |
| `adb_screen_resolution` | Get/set resolution          |
| `adb_package_info`      | Get package details         |
| `adb_running_processes` | List running processes      |
| `adb_focused_activity`  | Get focused activity        |

</details>

<details>
<summary>Frida Tools (38)</summary>

| Tool                      | Description                 |
| ------------------------- | --------------------------- |
| `frida_setup`             | Setup Frida on device       |
| `frida_list_processes`    | List processes              |
| `frida_list_apps`         | List applications           |
| `frida_attach`            | Attach to process           |
| `frida_spawn`             | Spawn and attach            |
| `frida_detach`            | Detach from process         |
| `frida_inject_script`     | Inject JavaScript           |
| `frida_inject_file`       | Inject script from file     |
| `frida_unload_script`     | Unload injected script      |
| `frida_enumerate_classes` | List Java classes           |
| `frida_enumerate_methods` | List class methods          |
| `frida_hook_method`       | Hook Java method            |
| `frida_hook_class`        | Hook all methods of class   |
| `frida_hook_constructor`  | Hook constructor            |
| `frida_hook_native`       | Hook native function        |
| `frida_replace_return`    | Replace method return value |
| `frida_trace_class`       | Trace class method calls    |
| `frida_memory_scan`       | Scan memory                 |
| `frida_read_memory`       | Read memory                 |
| `frida_write_memory`      | Write memory                |
| `frida_list_modules`      | List native modules         |
| `frida_list_exports`      | List module exports         |
| `frida_get_messages`      | Get Frida messages          |
| `frida_intercept_crypto`  | Intercept crypto calls      |
| `frida_intercept_http`    | Intercept HTTP calls        |
| `frida_intercept_intents` | Intercept Android intents   |
| `frida_intercept_prefs`   | Intercept SharedPreferences |
| `frida_intercept_sqlite`  | Intercept SQLite queries    |
| `frida_intercept_files`   | Intercept file operations   |
| `frida_android_info`      | Get Android device info     |
| `frida_find_instances`    | Find heap instances         |
| `frida_call_method`       | Call Java method            |
| `frida_get_field`         | Get field value             |
| `frida_set_field`         | Set field value             |
| `frida_get_class_info`    | Get detailed class info     |
| `frida_trace_native`      | Trace native calls          |
| `frida_list_imports`      | List module imports         |
| `frida_status`            | Get Frida session status    |

</details>

<details>
<summary>Bypass Tools (15)</summary>

| Tool                      | Description                          |
| ------------------------- | ------------------------------------ |
| `bypass_all`              | Apply all bypass scripts at once     |
| `bypass_ssl`              | SSL pinning bypass                   |
| `bypass_root`             | Root detection bypass                |
| `bypass_emulator`         | Emulator detection bypass            |
| `bypass_frida`            | Frida detection bypass               |
| `bypass_integrity`        | Integrity check bypass               |
| `bypass_scan`             | Scan for protection mechanisms       |
| `bypass_auto`             | Auto-detect and bypass all           |
| `bypass_rootbeer`         | RootBeer library bypass              |
| `bypass_gameguard`        | GameGuard bypass                     |
| `bypass_tencent`          | Tencent protection bypass            |
| `bypass_decompile_scan`   | Scan for protections via decompiling |
| `bypass_inject_universal` | Universal injection bypass           |
| `bypass_status`           | Check bypass status                  |
| `bypass_custom_class`     | Bypass custom class check            |

</details>

<details>
<summary>LDPlayer Management (19)</summary>

| Tool                  | Description                  |
| --------------------- | ---------------------------- |
| `ld_list_instances`   | List LDPlayer instances      |
| `ld_create_instance`  | Create new instance          |
| `ld_launch`           | Launch instance              |
| `ld_quit`             | Close instance               |
| `ld_reboot`           | Reboot instance              |
| `ld_modify_instance`  | Modify instance config       |
| `ld_set_location`     | Set GPS location             |
| `ld_install_app`      | Install app                  |
| `ld_backup`           | Backup instance              |
| `ld_restore`          | Restore instance             |
| `ld_clone`            | Clone instance               |
| `ld_device_profile`   | Set device profile           |
| `ld_set_root`         | Toggle root access           |
| `ld_shared_folder`    | Configure shared folder      |
| `ld_run_app`          | Run app                      |
| `ld_kill_app`         | Kill app                     |
| `ld_randomize_device` | Randomize device fingerprint |
| `ld_quit_all`         | Close all instances          |
| `ld_instance_config`  | Get instance configuration   |

</details>

<details>
<summary>Workflow & Utility (13)</summary>

| Tool                       | Description                    |
| -------------------------- | ------------------------------ |
| `workflow_full_intercept`  | Full app interception workflow |
| `workflow_quick_attach`    | Quick attach to running app    |
| `workflow_launch_emulator` | Launch emulator with setup     |
| `workflow_open_app`        | Open specific app              |
| `workflow_intercept_all`   | Start all interception         |
| `workflow_analyze`         | Full analysis workflow         |
| `workflow_collect_data`    | Collect all data               |
| `workflow_stop_all`        | Stop all active sessions       |
| `workflow_find_app`        | Find app by name               |
| `workflow_save_report`     | Save analysis report           |
| `workflow_status`          | Get workflow status            |
| `status`                   | Overall server status          |
| `help`                     | List available tools           |

</details>

### BlueStacks
**Server:** `bluestacks` · **Path:** `core/bluestacks/mcp_bluestacks.py` · **Tools:** 17

| Tool                | Description               |
| ------------------- | ------------------------- |
| `bs_list_instances` | List BlueStacks instances |
| `bs_launch`         | Launch instance           |
| `bs_stop`           | Stop instance             |
| `bs_install_apk`    | Install APK               |
| `bs_run_app`        | Run application           |
| `bs_adb_connect`    | Connect ADB               |
| `bs_screenshot`     | Take screenshot           |
| `bs_input`          | Simulate input            |
| `bs_shell`          | Run shell command         |
| `bs_get_config`     | Get configuration         |
| `bs_list_apps`      | List installed apps       |
| `bs_pull_file`      | Pull file                 |
| `bs_push_file`      | Push file                 |
| `bs_gps`            | Set GPS location          |
| `bs_set_config`     | Update configuration      |
| `bs_rotate`         | Rotate screen             |
| `bs_shake`          | Simulate shake gesture    |

### MEmu
**Server:** `memu` · **Path:** `core/memu/mcp_memu.py` · **Tools:** 19

| Tool                  | Description              |
| --------------------- | ------------------------ |
| `memu_list_instances` | List MEmu instances      |
| `memu_create`         | Create new instance      |
| `memu_start`          | Start instance           |
| `memu_stop`           | Stop instance            |
| `memu_install_apk`    | Install APK              |
| `memu_run_app`        | Run application          |
| `memu_adb_connect`    | Connect ADB              |
| `memu_shell`          | Run shell command        |
| `memu_screenshot`     | Take screenshot          |
| `memu_input`          | Simulate input           |
| `memu_set_config`     | Set configuration        |
| `memu_get_config`     | Get configuration        |
| `memu_clone`          | Clone instance           |
| `memu_list_apps`      | List installed apps      |
| `memu_pull`           | Pull file                |
| `memu_push`           | Push file                |
| `memu_gps`            | Set GPS location         |
| `memu_rotate`         | Rotate screen            |
| `memu_import_apk`     | Import APK into instance |

### Nox
**Server:** `nox` · **Path:** `core/nox/mcp_nox.py` · **Tools:** 22

| Tool                 | Description          |
| -------------------- | -------------------- |
| `nox_list_instances` | List Nox instances   |
| `nox_launch`         | Launch instance      |
| `nox_stop`           | Stop instance        |
| `nox_stop_all`       | Stop all instances   |
| `nox_create`         | Create new instance  |
| `nox_clone`          | Clone instance       |
| `nox_remove`         | Delete instance      |
| `nox_install_apk`    | Install APK          |
| `nox_run_app`        | Run application      |
| `nox_adb_connect`    | Connect ADB          |
| `nox_shell`          | Run shell command    |
| `nox_screenshot`     | Take screenshot      |
| `nox_input`          | Simulate input       |
| `nox_set_config`     | Set configuration    |
| `nox_get_config`     | Get configuration    |
| `nox_list_apps`      | List installed apps  |
| `nox_pull`           | Pull file            |
| `nox_push`           | Push file            |
| `nox_gps`            | Set GPS location     |
| `nox_rotate`         | Rotate screen        |
| `nox_root_toggle`    | Toggle root access   |
| `nox_macro`          | Run automation macro |

### ADB (Android Debug Bridge)
**Server:** `adb` · **Path:** `core/adb/mcp_adb.py` · **Tools:** 41

| Tool                 | Description              |
| -------------------- | ------------------------ |
| `adb_devices`        | List connected devices   |
| `adb_connect`        | Connect to device        |
| `adb_shell`          | Run shell command        |
| `adb_install`        | Install APK              |
| `adb_uninstall`      | Uninstall package        |
| `adb_push`           | Push file to device      |
| `adb_pull`           | Pull file from device    |
| `adb_logcat`         | Get logcat output        |
| `adb_screencap`      | Take screenshot          |
| `adb_input`          | Simulate input           |
| `adb_pm_list`        | List packages            |
| `adb_dumpsys`        | Run dumpsys              |
| `adb_getprop`        | Get system property      |
| `adb_setprop`        | Set system property      |
| `adb_forward`        | Set up port forward      |
| `adb_reverse`        | Set up reverse forward   |
| `adb_root`           | Restart as root          |
| `adb_remount`        | Remount /system          |
| `adb_reboot`         | Reboot device            |
| `adb_start_activity` | Start activity           |
| `adb_broadcast`      | Send broadcast           |
| `adb_kill_process`   | Kill process             |
| `adb_top`            | CPU/process monitor      |
| `adb_netstat`        | Network connections      |
| `adb_get_ip`         | Get device IP            |
| `adb_wifi_connect`   | Connect to WiFi          |
| `adb_backup`         | Full device backup       |
| `adb_screenrecord`   | Record screen            |
| `adb_get_apk_path`   | Get APK path for package |
| `adb_extract_apk`    | Extract APK from device  |
| `adb_tcp_dump`       | Capture network traffic  |
| `adb_bugreport`      | Generate bug report      |
| `adb_disable_verity` | Disable dm-verity        |
| `adb_sideload`       | Sideload OTA update      |
| `adb_list_features`  | List device features     |
| `adb_memory_info`    | Memory statistics        |
| `adb_battery_info`   | Battery info             |
| `adb_disk_info`      | Disk usage               |
| `adb_window_dump`    | Dump window hierarchy    |
| `adb_start_service`  | Start service            |
| `adb_clear_data`     | Clear app data           |

---

## Third-Party Servers

These servers are provided by npm packages or external tools:

| Server                | Package                                 | Description                   |
| --------------------- | --------------------------------------- | ----------------------------- |
| `filesystem`          | `@anthropic-ai/mcp-filesystem`          | File system operations        |
| `memory`              | `@anthropic-ai/mcp-memory`              | Persistent memory store       |
| `fetch`               | `@anthropic-ai/mcp-fetch`               | HTTP fetch requests           |
| `time`                | `@anthropic-ai/mcp-time`                | Time and timezone operations  |
| `sqlite`              | `@anthropic-ai/mcp-sqlite`              | SQLite database queries       |
| `git`                 | `@anthropic-ai/mcp-git`                 | Git operations                |
| `youtube-transcript`  | `@anthropic-ai/mcp-youtube-transcript`  | YouTube transcript extraction |
| `everything`          | `@anthropic-ai/mcp-everything`          | Universal search tool         |
| `sequential-thinking` | `@anthropic-ai/mcp-sequential-thinking` | Step-by-step reasoning        |
| `puppeteer`           | `@anthropic-ai/mcp-puppeteer`           | Browser automation            |
| `notepads`            | `@anthropic-ai/mcp-notepads`            | Notepad operations            |
| `context7`            | `@anthropic-ai/mcp-context7`            | Context management            |
| `playwright`          | `@anthropic-ai/mcp-playwright`          | Browser testing               |
| `github`              | `@anthropic-ai/mcp-github`              | GitHub API operations         |

---

## Quick Reference

### By Use Case

| Task                        | Tools to Use                                                  |
| --------------------------- | ------------------------------------------------------------- |
| **Translate/sanitize code** | `encode`, `decode`, `check`, `find_terms`                     |
| **Reverse APK**             | `jadx_decompile`, `apktool_decode`, `ag_analyze`              |
| **Hook app at runtime**     | `frida_hook_java`, `frida_hook_native`, `obj_android_hooking` |
| **Bypass protections**      | `bypass_all`, `frida_bypass_ssl`, `frida_bypass_root`         |
| **Scan for vulns**          | `nuclei_scan`, `nmap_vuln`, `burp_scan`, `nikto_scan`         |
| **Intercept traffic**       | `mitm_start_proxy`, `ws_capture`, `scapy_sniff`               |
| **Crack hashes**            | `hash_identify`, `hash_crack`, `hash_mask_attack`             |
| **Analyze binary**          | `ghidra_analyze`, `r2_analyze`, `r2_decompile`                |
| **Manage emulators**        | `ld_launch`, `bs_launch`, `memu_start`, `nox_launch`          |
| **Debug device**            | `adb_shell`, `adb_logcat`, `adb_dumpsys`                      |
