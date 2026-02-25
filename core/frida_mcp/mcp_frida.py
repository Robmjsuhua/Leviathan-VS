#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    LEVIATHAN VS - MCP Frida Server v1.0

    Standalone Frida MCP server for dynamic instrumentation.
    JSON-RPC 2.0 over stdio with Content-Length framing.

    Tools:
        - frida_list_devices: List Frida devices
        - frida_list_processes: List running processes
        - frida_list_apps: List installed applications
        - frida_inject_script: Inject JavaScript into target
        - frida_hook_java: Hook Java method (auto-generates script)
        - frida_hook_native: Hook native function (auto-generates script)
        - frida_memory_scan: Scan memory for pattern
        - frida_dump_classes: Dump all loaded Java classes
        - frida_dump_methods: Dump methods of a Java class
        - frida_heap_search: Search Java heap for instances
        - frida_bypass_ssl: Inject SSL pinning bypass
        - frida_bypass_root: Inject root detection bypass
        - frida_bypass_emulator: Inject emulator detection bypass
        - frida_bypass_frida: Inject Frida detection bypass
        - frida_dump_module: Dump native module info
        - frida_enumerate_exports: List exports of native module
        - frida_enumerate_imports: List imports of native module
        - frida_intercept_network: Hook send/recv for traffic interception
        - frida_xxtea_extract: Auto-extract XXTEA key from Cocos2d-x games
        - frida_generate_script: Generate predefined Frida scripts
        - frida_trace: Trace function calls matching pattern
        - frida_memory_read: Read raw memory at address
        - frida_memory_write: Write raw memory at address
        - frida_backtrace: Get native backtrace from function
        - frida_stalker_trace: CPU instruction trace with Stalker
        - frida_spawn_gating: Control app spawning
        - frida_enumerate_modules: List loaded native modules
        - frida_call_export: Call exported native function

    Author: ThiagoFrag / LEVIATHAN VS
    Version: 1.0.0
================================================================================
"""

import asyncio
import json
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("leviathan-frida-mcp")

VERSION = "1.0.0"
SERVER_NAME = "leviathan-frida-server"


def _find_frida() -> str:
    f = shutil.which("frida")
    return f if f else "frida"


def _find_frida_ps() -> str:
    f = shutil.which("frida-ps")
    return f if f else "frida-ps"


FRIDA = _find_frida()
FRIDA_PS = _find_frida_ps()

# ── Script Templates ──
SCRIPT_SSL_BYPASS = r"""
Java.perform(function() {
    // TrustManager bypass
    var TrustManager = Java.registerClass({
        name: 'leviathan.TrustManager',
        implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var ctx = SSLContext.getInstance('TLS');
    ctx.init(null, [TrustManager.$new()], null);
    SSLContext.getDefault.implementation = function() { return ctx; };

    // OkHttp3 CertificatePinner
    try {
        var CertPinner = Java.use('okhttp3.CertificatePinner');
        CertPinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {};
        CertPinner.check$okhttp.overload('java.lang.String', 'kotlin.jvm.functions.Function0').implementation = function() {};
    } catch(e) {}

    // HttpsURLConnection
    try {
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultSSLSocketFactory.implementation = function(factory) {};
        HttpsURLConnection.setSSLSocketFactory.implementation = function(factory) {};
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(verifier) {};
        HttpsURLConnection.setHostnameVerifier.implementation = function(verifier) {};
    } catch(e) {}

    send({type: 'ssl_bypass', status: 'active'});
});
"""

SCRIPT_ROOT_BYPASS = r"""
Java.perform(function() {
    // RootBeer
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        RootBeer.isRooted.implementation = function() { return false; };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() { return false; };
        RootBeer.detectRootManagementApps.implementation = function() { return false; };
        RootBeer.detectPotentiallyDangerousApps.implementation = function() { return false; };
        RootBeer.detectTestKeys.implementation = function() { return false; };
        RootBeer.checkForBusyBoxBinary.implementation = function() { return false; };
        RootBeer.checkForSuBinary.implementation = function() { return false; };
        RootBeer.checkSuExists.implementation = function() { return false; };
        RootBeer.checkForRWPaths.implementation = function() { return false; };
        RootBeer.checkForDangerousProps.implementation = function() { return false; };
        RootBeer.checkForRootNative.implementation = function() { return false; };
        RootBeer.detectRootCloakingApps.implementation = function() { return false; };
    } catch(e) {}

    // Generic su/root checks
    var Runtime = Java.use('java.lang.Runtime');
    var origExec = Runtime.exec.overload('[Ljava.lang.String;');
    origExec.implementation = function(cmd) {
        var blocked = ['su', 'which su', 'busybox', 'magisk'];
        for (var i = 0; i < blocked.length; i++) {
            if (cmd.toString().indexOf(blocked[i]) !== -1) {
                throw Java.use('java.io.IOException').$new('not found');
            }
        }
        return origExec.call(this, cmd);
    };

    // File.exists for su paths
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var blocked = ['/su', '/sbin/su', '/system/su', '/system/xbin/su', '/data/local/su',
                       '/magisk', '/sbin/magisk', 'Superuser.apk', 'SuperSU', 'busybox'];
        for (var i = 0; i < blocked.length; i++) {
            if (path.indexOf(blocked[i]) !== -1) return false;
        }
        return this.exists();
    };

    // Build.TAGS
    try {
        var Build = Java.use('android.os.Build');
        Build.TAGS.value = 'release-keys';
    } catch(e) {}

    send({type: 'root_bypass', status: 'active'});
});
"""

SCRIPT_EMULATOR_BYPASS = r"""
Java.perform(function() {
    var Build = Java.use('android.os.Build');
    Build.FINGERPRINT.value = 'google/walleye/walleye:8.1.0/OPM1.171019.021/4565141:user/release-keys';
    Build.MODEL.value = 'Pixel 2';
    Build.MANUFACTURER.value = 'Google';
    Build.BRAND.value = 'google';
    Build.DEVICE.value = 'walleye';
    Build.PRODUCT.value = 'walleye';
    Build.HARDWARE.value = 'walleye';
    Build.BOARD.value = 'walleye';
    Build.HOST.value = 'wphr1.hot.corp.google.com';

    // TelephonyManager
    try {
        var TelephonyManager = Java.use('android.telephony.TelephonyManager');
        TelephonyManager.getDeviceId.overload().implementation = function() { return '355458061189396'; };
        TelephonyManager.getSubscriberId.overload().implementation = function() { return '310260000000000'; };
        TelephonyManager.getLine1Number.overload().implementation = function() { return '+15555215554'; };
        TelephonyManager.getNetworkOperatorName.overload().implementation = function() { return 'T-Mobile'; };
        TelephonyManager.getSimOperatorName.overload().implementation = function() { return 'T-Mobile'; };
    } catch(e) {}

    // SystemProperties
    try {
        var SystemProperties = Java.use('android.os.SystemProperties');
        var origGet = SystemProperties.get.overload('java.lang.String');
        origGet.implementation = function(key) {
            var blocked = {'ro.hardware.chipname': 'exynos990', 'ro.kernel.qemu': '0',
                          'init.svc.qemud': '', 'init.svc.qemu-props': '',
                          'ro.product.model': 'Pixel 2', 'ro.product.brand': 'google',
                          'ro.secure': '1', 'ro.debuggable': '0'};
            if (key in blocked) return blocked[key];
            return origGet.call(this, key);
        };
    } catch(e) {}

    send({type: 'emulator_bypass', status: 'active'});
});
"""

SCRIPT_FRIDA_BYPASS = r"""
// Anti-Frida detection bypass
Interceptor.attach(Module.findExportByName(null, 'open'), {
    onEnter: function(args) {
        this.path = args[0].readUtf8String();
    },
    onLeave: function(retval) {
        if (this.path && (this.path.indexOf('frida') !== -1 || this.path.indexOf('gadget') !== -1)) {
            retval.replace(ptr(-1));
        }
    }
});

Interceptor.attach(Module.findExportByName(null, 'strstr'), {
    onEnter: function(args) {
        this.haystack = args[0].readUtf8String();
        this.needle = args[1].readUtf8String();
    },
    onLeave: function(retval) {
        if (this.needle && (this.needle.indexOf('frida') !== -1 || this.needle.indexOf('LIBFRIDA') !== -1 ||
            this.needle.indexOf('gum-js-loop') !== -1 || this.needle.indexOf('gmain') !== -1)) {
            retval.replace(ptr(0));
        }
    }
});

// Port scanning anti-frida
Java.perform(function() {
    try {
        var Socket = Java.use('java.net.Socket');
        Socket.$init.overload('java.lang.String', 'int').implementation = function(host, port) {
            if (port === 27042 || port === 27043) {
                throw Java.use('java.net.ConnectException').$new('Connection refused');
            }
            return this.$init(host, port);
        };
    } catch(e) {}
});

send({type: 'frida_bypass', status: 'active'});
"""

SCRIPT_XXTEA_KEY = r"""
// Auto-extract XXTEA key from Cocos2d-x
var modules = ['libcocos2dlua.so', 'libcocos2dcpp.so', 'libgame.so', 'libcocos2d.so'];
modules.forEach(function(modName) {
    try {
        var mod = Process.findModuleByName(modName);
        if (!mod) return;

        // Hook xxtea_decrypt
        var funcs = ['xxtea_decrypt', '_Z13xxtea_decryptPKhjS0_jPj', 'xxtea_tobytes'];
        funcs.forEach(function(fname) {
            try {
                var addr = Module.findExportByName(modName, fname);
                if (!addr) return;
                Interceptor.attach(addr, {
                    onEnter: function(args) {
                        try {
                            this.key = args[2].readUtf8String();
                            this.keyLen = args[3].toInt32();
                            send({type: 'xxtea_key', module: modName, func: fname,
                                  key: this.key, keyLen: this.keyLen});
                        } catch(e) {}
                    }
                });
                send({type: 'hook_installed', module: modName, func: fname});
            } catch(e) {}
        });

        // Memory scan for common XXTEA patterns
        Memory.scan(mod.base, mod.size, '78 78 74 65 61', {
            onMatch: function(addr, size) {
                try {
                    var str = addr.readUtf8String();
                    send({type: 'xxtea_string_found', addr: addr.toString(), value: str});
                } catch(e) {}
            },
            onComplete: function() {}
        });
    } catch(e) {}
});
"""

SCRIPT_NETWORK_INTERCEPT = (
    r"""
// Hook send/recv for network traffic interception
['send', 'recv', 'write', 'read'].forEach(function(fname) {
    try {
        Interceptor.attach(Module.findExportByName(null, fname), {
            onEnter: function(args) {
                this.fd = args[0].toInt32();
                this.buf = args[1];
                this.len = args[2].toInt32();
            },
            onLeave: function(retval) {
                var bytesTransferred = retval.toInt32();
                if (bytesTransferred > 0 && bytesTransferred < 65536) {
                    try {
                        var data = this.buf.readByteArray(bytesTransferred);
                        send({type: 'network', func: '"""
    + "'"
    + r"""' + fname, fd: this.fd,
                              length: bytesTransferred}, data);
                    } catch(e) {}
                }
            }
        });
    } catch(e) {}
});

// Hook Java network
Java.perform(function() {
    try {
        var URL = Java.use('java.net.URL');
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        URL.openConnection.overload().implementation = function() {
            var conn = this.openConnection();
            send({type: 'http_request', url: this.toString()});
            return conn;
        };
    } catch(e) {}

    // OkHttp3
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var RealCall = Java.use('okhttp3.RealCall');
        RealCall.execute.implementation = function() {
            var req = this.request();
            send({type: 'okhttp_request', url: req.url().toString(), method: req.method()});
            return this.execute();
        };
    } catch(e) {}
});
"""
)


def _run_frida_cmd(args: List[str], timeout: int = 30) -> Dict:
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        return {
            "success": proc.returncode == 0,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"Timeout after {timeout}s"}
    except Exception as e:
        return {"success": False, "error": str(e)}


TOOLS = [
    {
        "name": "frida_list_devices",
        "description": "Lista dispositivos Frida conectados (USB, remote, local)",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "frida_list_processes",
        "description": "Lista processos rodando no dispositivo",
        "inputSchema": {
            "type": "object",
            "properties": {
                "device": {"type": "string", "description": "Device ID (default: USB)"},
                "grep": {"type": "string", "description": "Filtrar por nome"},
            },
        },
    },
    {
        "name": "frida_list_apps",
        "description": "Lista apps instalados no dispositivo",
        "inputSchema": {
            "type": "object",
            "properties": {
                "device": {"type": "string"},
                "installed_only": {"type": "boolean"},
            },
        },
    },
    {
        "name": "frida_inject_script",
        "description": "Injeta script JavaScript Frida em processo. Retorna output por 5s",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "PID ou nome do pacote"},
                "script": {
                    "type": "string",
                    "description": "Codigo JavaScript Frida completo",
                },
                "spawn": {"type": "boolean", "description": "Spawn ao inves de attach"},
                "device": {"type": "string"},
                "timeout": {
                    "type": "integer",
                    "description": "Tempo de captura em segundos (default 5)",
                },
            },
            "required": ["target", "script"],
        },
    },
    {
        "name": "frida_hook_java",
        "description": "Gera e injeta hook para metodo Java. Loga argumentos e retorno",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "PID ou pacote"},
                "class_name": {
                    "type": "string",
                    "description": "Nome completo da classe Java",
                },
                "method_name": {"type": "string", "description": "Nome do metodo"},
                "modify_return": {
                    "type": "string",
                    "description": "Valor para substituir retorno (opcional)",
                },
                "device": {"type": "string"},
            },
            "required": ["target", "class_name", "method_name"],
        },
    },
    {
        "name": "frida_hook_native",
        "description": "Gera e injeta hook para funcao nativa (C/C++)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "module": {"type": "string", "description": "Nome do modulo .so"},
                "function": {
                    "type": "string",
                    "description": "Nome da funcao exportada",
                },
                "num_args": {
                    "type": "integer",
                    "description": "Numero de argumentos a logar",
                },
                "modify_return": {
                    "type": "string",
                    "description": "Novo valor de retorno",
                },
                "device": {"type": "string"},
            },
            "required": ["target", "module", "function"],
        },
    },
    {
        "name": "frida_memory_scan",
        "description": "Busca padrao hex na memoria de um modulo",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "module": {"type": "string", "description": "Nome do modulo"},
                "pattern": {
                    "type": "string",
                    "description": "Pattern hex (ex: 'DE AD BE EF')",
                },
                "device": {"type": "string"},
            },
            "required": ["target", "module", "pattern"],
        },
    },
    {
        "name": "frida_dump_classes",
        "description": "Lista todas as classes Java carregadas (filtravel)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "filter": {
                    "type": "string",
                    "description": "Filtro de nome (ex: 'com.game')",
                },
                "device": {"type": "string"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "frida_dump_methods",
        "description": "Lista todos os metodos de uma classe Java",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "class_name": {"type": "string"},
                "device": {"type": "string"},
            },
            "required": ["target", "class_name"],
        },
    },
    {
        "name": "frida_heap_search",
        "description": "Busca instancias de classe no heap Java",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "class_name": {"type": "string"},
                "device": {"type": "string"},
            },
            "required": ["target", "class_name"],
        },
    },
    {
        "name": "frida_bypass_ssl",
        "description": "Injeta bypass universal de SSL pinning",
        "inputSchema": {
            "type": "object",
            "properties": {"target": {"type": "string"}, "device": {"type": "string"}},
            "required": ["target"],
        },
    },
    {
        "name": "frida_bypass_root",
        "description": "Injeta bypass de deteccao de root",
        "inputSchema": {
            "type": "object",
            "properties": {"target": {"type": "string"}, "device": {"type": "string"}},
            "required": ["target"],
        },
    },
    {
        "name": "frida_bypass_emulator",
        "description": "Injeta bypass de deteccao de emulador",
        "inputSchema": {
            "type": "object",
            "properties": {"target": {"type": "string"}, "device": {"type": "string"}},
            "required": ["target"],
        },
    },
    {
        "name": "frida_bypass_frida",
        "description": "Injeta bypass de deteccao de Frida",
        "inputSchema": {
            "type": "object",
            "properties": {"target": {"type": "string"}, "device": {"type": "string"}},
            "required": ["target"],
        },
    },
    {
        "name": "frida_dump_module",
        "description": "Dump info completo de modulo nativo (base, size, exports count)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "module": {"type": "string"},
                "device": {"type": "string"},
            },
            "required": ["target", "module"],
        },
    },
    {
        "name": "frida_enumerate_exports",
        "description": "Lista todas as funcoes exportadas de um modulo nativo",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "module": {"type": "string"},
                "filter": {"type": "string"},
                "device": {"type": "string"},
            },
            "required": ["target", "module"],
        },
    },
    {
        "name": "frida_enumerate_imports",
        "description": "Lista todas as funcoes importadas de um modulo nativo",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "module": {"type": "string"},
                "filter": {"type": "string"},
                "device": {"type": "string"},
            },
            "required": ["target", "module"],
        },
    },
    {
        "name": "frida_intercept_network",
        "description": "Intercepta trafego de rede (send/recv/HTTP/OkHttp)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "device": {"type": "string"},
                "timeout": {"type": "integer"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "frida_xxtea_extract",
        "description": "Auto-extrai chave XXTEA de jogos Cocos2d-x via hooking",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "device": {"type": "string"},
                "timeout": {"type": "integer"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "frida_generate_script",
        "description": "Gera script Frida customizado baseado em descricao",
        "inputSchema": {
            "type": "object",
            "properties": {
                "type": {
                    "type": "string",
                    "enum": [
                        "ssl_bypass",
                        "root_bypass",
                        "emulator_bypass",
                        "frida_bypass",
                        "xxtea_key",
                        "network_intercept",
                        "java_trace_all",
                        "native_hook",
                    ],
                    "description": "Tipo de script",
                },
                "params": {
                    "type": "object",
                    "description": "Parametros especificos do tipo",
                },
            },
            "required": ["type"],
        },
    },
    {
        "name": "frida_trace",
        "description": "Traca chamadas de funcao que correspondem a um pattern",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Nome do processo ou pacote",
                },
                "pattern": {
                    "type": "string",
                    "description": "Pattern de funcao (ex: *!open*, *ssl*)",
                },
                "spawn": {"type": "boolean"},
                "device": {"type": "string"},
                "timeout": {"type": "integer"},
            },
            "required": ["target", "pattern"],
        },
    },
    {
        "name": "frida_memory_read",
        "description": "Le memoria raw em endereco especifico",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "address": {
                    "type": "string",
                    "description": "Endereco hex (ex: 0x7fff1234)",
                },
                "size": {
                    "type": "integer",
                    "description": "Bytes a ler (default: 256)",
                },
                "spawn": {"type": "boolean"},
                "device": {"type": "string"},
                "timeout": {"type": "integer"},
            },
            "required": ["target", "address"],
        },
    },
    {
        "name": "frida_memory_write",
        "description": "Escreve bytes na memoria do processo",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "address": {"type": "string", "description": "Endereco hex"},
                "hex_bytes": {
                    "type": "string",
                    "description": "Bytes em hex (ex: 90909090)",
                },
                "spawn": {"type": "boolean"},
                "device": {"type": "string"},
                "timeout": {"type": "integer"},
            },
            "required": ["target", "address", "hex_bytes"],
        },
    },
    {
        "name": "frida_backtrace",
        "description": "Obtem backtrace nativo ao entrar em funcao",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "function": {
                    "type": "string",
                    "description": "Nome da funcao ou endereco",
                },
                "module": {"type": "string", "description": "Modulo da funcao"},
                "spawn": {"type": "boolean"},
                "device": {"type": "string"},
                "timeout": {"type": "integer"},
            },
            "required": ["target", "function"],
        },
    },
    {
        "name": "frida_stalker_trace",
        "description": "CPU instruction trace com Frida Stalker",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "function": {
                    "type": "string",
                    "description": "Funcao alvo para tracar",
                },
                "module": {"type": "string"},
                "max_instructions": {
                    "type": "integer",
                    "description": "Max instrucoes (default: 1000)",
                },
                "spawn": {"type": "boolean"},
                "device": {"type": "string"},
                "timeout": {"type": "integer"},
            },
            "required": ["target", "function"],
        },
    },
    {
        "name": "frida_spawn_gating",
        "description": "Controla spawning de apps (enable/disable spawn gating)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["enable", "disable", "list"],
                    "description": "Acao",
                },
                "device": {"type": "string"},
            },
            "required": ["action"],
        },
    },
    {
        "name": "frida_enumerate_modules",
        "description": "Lista modulos nativos carregados no processo",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "filter": {"type": "string", "description": "Filtro por nome"},
                "spawn": {"type": "boolean"},
                "device": {"type": "string"},
                "timeout": {"type": "integer"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "frida_call_export",
        "description": "Chama funcao exportada de modulo nativo",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "module": {"type": "string", "description": "Nome do modulo"},
                "export_name": {
                    "type": "string",
                    "description": "Nome da funcao exportada",
                },
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Argumentos (hex ou numeros)",
                },
                "spawn": {"type": "boolean"},
                "device": {"type": "string"},
                "timeout": {"type": "integer"},
            },
            "required": ["target", "module", "export_name"],
        },
    },
]


def _build_inject_cmd(
    target: str,
    script_content: str,
    spawn: bool = False,
    device: str = "",
    timeout: int = 5,
) -> tuple:
    """Build frida CLI command for script injection."""
    import tempfile

    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".js", delete=False, encoding="utf-8"
    )
    tmp.write(script_content)
    tmp.close()

    cmd = [FRIDA]
    if device:
        cmd.extend(["-D", device])
    else:
        cmd.append("-U")  # default USB

    if spawn:
        cmd.extend(["-f", target, "-l", tmp.name, "--no-pause"])
    else:
        cmd.extend([target, "-l", tmp.name])

    return cmd, tmp.name


async def dispatch_tool(name: str, args: Dict) -> str:
    device = args.get("device", "")

    if name == "frida_list_devices":
        r = _run_frida_cmd([FRIDA_PS, "-D", "all"] if False else [FRIDA, "--version"])
        # Use frida-ls-devices
        ls = shutil.which("frida-ls-devices")
        if ls:
            r = _run_frida_cmd([ls])
        else:
            r = _run_frida_cmd([FRIDA_PS, "-R"] if False else [FRIDA_PS, "-U"])
        return r.get("stdout", r.get("error", "No devices"))

    elif name == "frida_list_processes":
        cmd = [FRIDA_PS]
        if device:
            cmd.extend(["-D", device])
        else:
            cmd.append("-U")
        r = _run_frida_cmd(cmd, timeout=15)
        output = r.get("stdout", "")
        if args.get("grep") and output:
            output = "\n".join(
                l for l in output.splitlines() if args["grep"].lower() in l.lower()
            )
        return output if output else r.get("error", "No processes")

    elif name == "frida_list_apps":
        cmd = [FRIDA_PS]
        if device:
            cmd.extend(["-D", device])
        else:
            cmd.append("-U")
        cmd.extend(["-a", "-i"] if not args.get("installed_only") else ["-a"])
        r = _run_frida_cmd(cmd, timeout=15)
        return r.get("stdout", r.get("error", ""))

    elif name == "frida_inject_script":
        timeout = args.get("timeout", 5)
        cmd, tmpfile = _build_inject_cmd(
            args["target"], args["script"], args.get("spawn", False), device, timeout
        )
        r = _run_frida_cmd(cmd, timeout=timeout + 5)
        try:
            os.unlink(tmpfile)
        except Exception:
            pass
        return r.get("stdout", "") + "\n" + r.get("stderr", "")

    elif name == "frida_hook_java":
        modify = args.get("modify_return", "")
        script = f"""
Java.perform(function() {{
    var clazz = Java.use("{args['class_name']}");
    var overloads = clazz.{args['method_name']}.overloads;
    overloads.forEach(function(overload) {{
        overload.implementation = function() {{
            var a = Array.prototype.slice.call(arguments);
            console.log("[HOOK] {args['class_name']}.{args['method_name']}(" + a.join(", ") + ")");
            {"var ret = " + modify + ";" if modify else "var ret = this." + args['method_name'] + ".apply(this, arguments);"}
            console.log("[HOOK] => " + ret);
            return ret;
        }};
    }});
    console.log("[+] Hooked {args['class_name']}.{args['method_name']}");
}});"""
        cmd, tmpfile = _build_inject_cmd(args["target"], script, False, device, 5)
        r = _run_frida_cmd(cmd, timeout=10)
        try:
            os.unlink(tmpfile)
        except Exception:
            pass
        return f"Script:\n{script}\n\nOutput:\n{r.get('stdout', '')}\n{r.get('stderr', '')}"

    elif name == "frida_hook_native":
        num_args = args.get("num_args", 4)
        modify = args.get("modify_return", "")
        args_log = "\n".join(
            f'        console.log("    arg{i}: " + args[{i}]);' for i in range(num_args)
        )
        script = f"""
var addr = Module.findExportByName("{args['module']}", "{args['function']}");
if (addr) {{
    Interceptor.attach(addr, {{
        onEnter: function(args) {{
            console.log("[HOOK] {args['module']}!{args['function']} called");
{args_log}
            console.log("    backtrace: " + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\\n    "));
        }},
        onLeave: function(retval) {{
            console.log("[HOOK] => " + retval);
            {"retval.replace(ptr(" + modify + "));" if modify else ""}
        }}
    }});
    console.log("[+] Hooked {args['function']} at " + addr);
}} else {{
    console.log("[-] Function not found: {args['function']}");
}}"""
        cmd, tmpfile = _build_inject_cmd(args["target"], script, False, device, 5)
        r = _run_frida_cmd(cmd, timeout=10)
        try:
            os.unlink(tmpfile)
        except Exception:
            pass
        return f"Script:\n{script}\n\nOutput:\n{r.get('stdout', '')}\n{r.get('stderr', '')}"

    elif name == "frida_memory_scan":
        script = f"""
var mod = Process.findModuleByName("{args['module']}");
if (mod) {{
    console.log("[*] Scanning " + mod.name + " (base=" + mod.base + " size=" + mod.size + ")");
    Memory.scan(mod.base, mod.size, "{args['pattern']}", {{
        onMatch: function(addr, size) {{
            console.log("[MATCH] " + addr + " : " + hexdump(addr, {{length: 64}}));
        }},
        onComplete: function() {{ console.log("[*] Scan complete"); }}
    }});
}} else {{ console.log("[-] Module not found"); }}"""
        cmd, tmpfile = _build_inject_cmd(args["target"], script, False, device, 10)
        r = _run_frida_cmd(cmd, timeout=15)
        try:
            os.unlink(tmpfile)
        except Exception:
            pass
        return r.get("stdout", "") + "\n" + r.get("stderr", "")

    elif name == "frida_dump_classes":
        filt = args.get("filter", "")
        script = f"""
Java.perform(function() {{
    Java.enumerateLoadedClasses({{
        onMatch: function(name) {{
            {"if (name.indexOf('" + filt + "') !== -1)" if filt else ""}
                console.log(name);
        }},
        onComplete: function() {{ console.log("[*] Done"); }}
    }});
}});"""
        cmd, tmpfile = _build_inject_cmd(args["target"], script, False, device, 10)
        r = _run_frida_cmd(cmd, timeout=15)
        try:
            os.unlink(tmpfile)
        except Exception:
            pass
        return r.get("stdout", "") + "\n" + r.get("stderr", "")

    elif name == "frida_dump_methods":
        script = f"""
Java.perform(function() {{
    var clazz = Java.use("{args['class_name']}");
    var methods = clazz.class.getDeclaredMethods();
    console.log("[*] Methods of {args['class_name']}:");
    for (var i = 0; i < methods.length; i++) {{
        console.log("  " + methods[i].toString());
    }}
    var fields = clazz.class.getDeclaredFields();
    console.log("[*] Fields:");
    for (var i = 0; i < fields.length; i++) {{
        console.log("  " + fields[i].toString());
    }}
}});"""
        cmd, tmpfile = _build_inject_cmd(args["target"], script, False, device, 5)
        r = _run_frida_cmd(cmd, timeout=10)
        try:
            os.unlink(tmpfile)
        except Exception:
            pass
        return r.get("stdout", "") + "\n" + r.get("stderr", "")

    elif name == "frida_heap_search":
        script = f"""
Java.perform(function() {{
    Java.choose("{args['class_name']}", {{
        onMatch: function(instance) {{
            console.log("[HEAP] " + instance.toString());
            try {{ console.log("       " + JSON.stringify(instance)); }} catch(e) {{}}
        }},
        onComplete: function() {{ console.log("[*] Heap search complete"); }}
    }});
}});"""
        cmd, tmpfile = _build_inject_cmd(args["target"], script, False, device, 5)
        r = _run_frida_cmd(cmd, timeout=10)
        try:
            os.unlink(tmpfile)
        except Exception:
            pass
        return r.get("stdout", "") + "\n" + r.get("stderr", "")

    elif name in (
        "frida_bypass_ssl",
        "frida_bypass_root",
        "frida_bypass_emulator",
        "frida_bypass_frida",
    ):
        scripts = {
            "frida_bypass_ssl": SCRIPT_SSL_BYPASS,
            "frida_bypass_root": SCRIPT_ROOT_BYPASS,
            "frida_bypass_emulator": SCRIPT_EMULATOR_BYPASS,
            "frida_bypass_frida": SCRIPT_FRIDA_BYPASS,
        }
        script = scripts[name]
        cmd, tmpfile = _build_inject_cmd(args["target"], script, False, device, 5)
        r = _run_frida_cmd(cmd, timeout=10)
        try:
            os.unlink(tmpfile)
        except Exception:
            pass
        return (
            f"Bypass injected.\nOutput:\n{r.get('stdout', '')}\n{r.get('stderr', '')}"
        )

    elif name == "frida_dump_module":
        script = f"""
var mod = Process.findModuleByName("{args['module']}");
if (mod) {{
    console.log("Name: " + mod.name);
    console.log("Base: " + mod.base);
    console.log("Size: " + mod.size);
    console.log("Path: " + mod.path);
    var exports = mod.enumerateExports();
    console.log("Exports: " + exports.length);
    var imports = mod.enumerateImports();
    console.log("Imports: " + imports.length);
}} else {{ console.log("Module not found"); }}"""
        cmd, tmpfile = _build_inject_cmd(args["target"], script, False, device, 5)
        r = _run_frida_cmd(cmd, timeout=10)
        try:
            os.unlink(tmpfile)
        except Exception:
            pass
        return r.get("stdout", "") + "\n" + r.get("stderr", "")

    elif name == "frida_enumerate_exports":
        filt = args.get("filter", "")
        script = f"""
var mod = Process.findModuleByName("{args['module']}");
if (mod) {{
    mod.enumerateExports().forEach(function(exp) {{
        {"if (exp.name.toLowerCase().indexOf('" + filt.lower() + "') !== -1)" if filt else ""}
            console.log(exp.type + " " + exp.name + " @ " + exp.address);
    }});
}} else {{ console.log("Module not found"); }}"""
        cmd, tmpfile = _build_inject_cmd(args["target"], script, False, device, 10)
        r = _run_frida_cmd(cmd, timeout=15)
        try:
            os.unlink(tmpfile)
        except Exception:
            pass
        return r.get("stdout", "") + "\n" + r.get("stderr", "")

    elif name == "frida_enumerate_imports":
        filt = args.get("filter", "")
        script = f"""
var mod = Process.findModuleByName("{args['module']}");
if (mod) {{
    mod.enumerateImports().forEach(function(imp) {{
        {"if (imp.name.toLowerCase().indexOf('" + filt.lower() + "') !== -1)" if filt else ""}
            console.log(imp.type + " " + imp.name + " from " + imp.module + " @ " + imp.address);
    }});
}} else {{ console.log("Module not found"); }}"""
        cmd, tmpfile = _build_inject_cmd(args["target"], script, False, device, 10)
        r = _run_frida_cmd(cmd, timeout=15)
        try:
            os.unlink(tmpfile)
        except Exception:
            pass
        return r.get("stdout", "") + "\n" + r.get("stderr", "")

    elif name == "frida_intercept_network":
        timeout = args.get("timeout", 10)
        cmd, tmpfile = _build_inject_cmd(
            args["target"], SCRIPT_NETWORK_INTERCEPT, False, device, timeout
        )
        r = _run_frida_cmd(cmd, timeout=timeout + 5)
        try:
            os.unlink(tmpfile)
        except Exception:
            pass
        return r.get("stdout", "") + "\n" + r.get("stderr", "")

    elif name == "frida_xxtea_extract":
        timeout = args.get("timeout", 15)
        cmd, tmpfile = _build_inject_cmd(
            args["target"], SCRIPT_XXTEA_KEY, False, device, timeout
        )
        r = _run_frida_cmd(cmd, timeout=timeout + 5)
        try:
            os.unlink(tmpfile)
        except Exception:
            pass
        return r.get("stdout", "") + "\n" + r.get("stderr", "")

    elif name == "frida_generate_script":
        scripts = {
            "ssl_bypass": SCRIPT_SSL_BYPASS,
            "root_bypass": SCRIPT_ROOT_BYPASS,
            "emulator_bypass": SCRIPT_EMULATOR_BYPASS,
            "frida_bypass": SCRIPT_FRIDA_BYPASS,
            "xxtea_key": SCRIPT_XXTEA_KEY,
            "network_intercept": SCRIPT_NETWORK_INTERCEPT,
        }
        stype = args.get("type", "")
        if stype in scripts:
            return f"// Generated {stype} script\n{scripts[stype]}"
        return f"Unknown script type: {stype}. Available: {', '.join(scripts.keys())}"

    elif name == "frida_trace":
        trace_bin = shutil.which("frida-trace") or "frida-trace"
        cmd = [trace_bin]
        if args.get("spawn"):
            cmd += ["-f", args["target"]]
        else:
            cmd += ["-n", args["target"]]
        if args.get("device"):
            cmd += ["-D", args["device"]]
        cmd += ["-i", args["pattern"]]
        timeout = args.get("timeout", 15)
        r = _run_frida_cmd(cmd, timeout=timeout)
        return r.get("stdout", "") + "\n" + r.get("stderr", "")

    elif name == "frida_memory_read":
        size = args.get("size", 256)
        script = f"""
var addr = ptr('{args["address"]}');
var buf = Memory.readByteArray(addr, {size});
var hex = '';
var view = new Uint8Array(buf);
for (var i = 0; i < view.length; i++) {{
    hex += ('0' + view[i].toString(16)).slice(-2);
    if ((i + 1) % 16 === 0) hex += '\\n'; else hex += ' ';
}}
send(hex);
"""
        cmd, tmpfile = _build_inject_cmd(
            args["target"], script, args.get("spawn", False), args.get("device", "")
        )
        r = _run_frida_cmd(cmd, timeout=args.get("timeout", 15))
        try:
            os.unlink(tmpfile)
        except Exception:
            pass
        return r.get("stdout", "") + "\n" + r.get("stderr", "")

    elif name == "frida_memory_write":
        hex_bytes = args["hex_bytes"]
        byte_array = ", ".join(
            f"0x{hex_bytes[i:i+2]}" for i in range(0, len(hex_bytes), 2)
        )
        script = f"""
var addr = ptr('{args["address"]}');
Memory.protect(addr, {len(hex_bytes)//2}, 'rwx');
var bytes = [{byte_array}];
Memory.writeByteArray(addr, bytes);
send('Written ' + bytes.length + ' bytes to ' + addr);
"""
        cmd, tmpfile = _build_inject_cmd(
            args["target"], script, args.get("spawn", False), args.get("device", "")
        )
        r = _run_frida_cmd(cmd, timeout=args.get("timeout", 15))
        try:
            os.unlink(tmpfile)
        except Exception:
            pass
        return r.get("stdout", "") + "\n" + r.get("stderr", "")

    elif name == "frida_backtrace":
        func = args["function"]
        module = args.get("module", "")
        if module:
            hook = f"Module.findExportByName('{module}', '{func}')"
        elif func.startswith("0x"):
            hook = f"ptr('{func}')"
        else:
            hook = f"Module.findExportByName(null, '{func}')"
        script = f"""
Interceptor.attach({hook}, {{
    onEnter: function(args) {{
        send('Backtrace from {func}:\\n' +
            Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join('\\n'));
    }}
}});
"""
        cmd, tmpfile = _build_inject_cmd(
            args["target"], script, args.get("spawn", False), args.get("device", "")
        )
        r = _run_frida_cmd(cmd, timeout=args.get("timeout", 15))
        try:
            os.unlink(tmpfile)
        except Exception:
            pass
        return r.get("stdout", "") + "\n" + r.get("stderr", "")

    elif name == "frida_stalker_trace":
        func = args["function"]
        module = args.get("module", "")
        max_instr = args.get("max_instructions", 1000)
        if module:
            hook = f"Module.findExportByName('{module}', '{func}')"
        elif func.startswith("0x"):
            hook = f"ptr('{func}')"
        else:
            hook = f"Module.findExportByName(null, '{func}')"
        script = f"""
var count = 0;
Interceptor.attach({hook}, {{
    onEnter: function(args) {{
        Stalker.follow(this.threadId, {{
            events: {{ call: true, ret: false, exec: false }},
            onCallSummary: function(summary) {{
                var entries = Object.entries(summary).slice(0, {max_instr});
                var result = entries.map(function(e) {{
                    var sym = DebugSymbol.fromAddress(ptr(e[0]));
                    return sym + ' (' + e[1] + ' calls)';
                }}).join('\\n');
                send(result);
                Stalker.unfollow(this.threadId);
            }}
        }});
    }}
}});
"""
        cmd, tmpfile = _build_inject_cmd(
            args["target"], script, args.get("spawn", False), args.get("device", "")
        )
        r = _run_frida_cmd(cmd, timeout=args.get("timeout", 20))
        try:
            os.unlink(tmpfile)
        except Exception:
            pass
        return r.get("stdout", "") + "\n" + r.get("stderr", "")

    elif name == "frida_spawn_gating":
        action = args["action"]
        frida_bin = shutil.which("frida") or "frida"
        device_args = ["-D", args["device"]] if args.get("device") else []
        if action == "enable":
            script = "Frida.enableSpawnGating(); send('Spawn gating enabled');"
        elif action == "disable":
            script = "Frida.disableSpawnGating(); send('Spawn gating disabled');"
        else:
            script = "var pending = Frida.enumeratePendingSpawn(); send(JSON.stringify(pending));"
        cmd = [frida_bin] + device_args + ["-e", script]
        r = _run_frida_cmd(cmd, timeout=10)
        return r.get("stdout", "") + "\n" + r.get("stderr", "")

    elif name == "frida_enumerate_modules":
        script = """
Process.enumerateModules().forEach(function(m) {
    send(m.name + ' | base=' + m.base + ' | size=' + m.size + ' | path=' + m.path);
});
"""
        cmd, tmpfile = _build_inject_cmd(
            args["target"], script, args.get("spawn", False), args.get("device", "")
        )
        r = _run_frida_cmd(cmd, timeout=args.get("timeout", 15))
        try:
            os.unlink(tmpfile)
        except Exception:
            pass
        output = r.get("stdout", "") + "\n" + r.get("stderr", "")
        if args.get("filter"):
            output = "\n".join(
                l for l in output.splitlines() if args["filter"].lower() in l.lower()
            )
        return output

    elif name == "frida_call_export":
        module = args["module"]
        export = args["export_name"]
        call_args = args.get("args", [])
        args_js = ", ".join(
            f"ptr('{a}')" if a.startswith("0x") else a for a in call_args
        )
        script = f"""
var func = Module.findExportByName('{module}', '{export}');
if (func) {{
    var nf = new NativeFunction(func, 'pointer', [{', '.join(["'pointer'" for _ in call_args])}]);
    var result = nf({args_js});
    send('Result: ' + result);
}} else {{
    send('Export {export} not found in {module}');
}}
"""
        cmd, tmpfile = _build_inject_cmd(
            args["target"], script, args.get("spawn", False), args.get("device", "")
        )
        r = _run_frida_cmd(cmd, timeout=args.get("timeout", 15))
        try:
            os.unlink(tmpfile)
        except Exception:
            pass
        return r.get("stdout", "") + "\n" + r.get("stderr", "")

    return f"Unknown tool: {name}"


# ── MCP Server ──
class MCPServer:
    def __init__(self):
        self.running = True

    def _response(self, id, result):
        return {"jsonrpc": "2.0", "id": id, "result": result}

    def _error(self, id, code, msg):
        return {"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": msg}}

    async def handle(self, req):
        method = req.get("method", "")
        params = req.get("params", {})
        rid = req.get("id")

        if method == "initialize":
            return self._response(
                rid,
                {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {"name": SERVER_NAME, "version": VERSION},
                    "capabilities": {"tools": {"listChanged": False}},
                },
            )
        elif method == "initialized":
            return None
        elif method == "shutdown":
            self.running = False
            return self._response(rid, None)
        elif method == "tools/list":
            return self._response(rid, {"tools": TOOLS})
        elif method == "tools/call":
            name = params.get("name", "")
            tool_args = params.get("arguments", {})
            try:
                result = await dispatch_tool(name, tool_args)
                return self._response(
                    rid, {"content": [{"type": "text", "text": str(result)}]}
                )
            except Exception as e:
                return self._response(
                    rid,
                    {
                        "content": [{"type": "text", "text": f"ERROR: {e}"}],
                        "isError": True,
                    },
                )
        elif method == "resources/list":
            return self._response(rid, {"resources": []})
        elif method == "prompts/list":
            return self._response(rid, {"prompts": []})
        elif method.startswith("notifications/"):
            return None
        else:
            return self._error(rid, -32601, f"Unknown method: {method}")

    async def run(self):
        if sys.platform == "win32":
            import msvcrt

            msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
            msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)

        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(
            lambda: protocol, sys.stdin.buffer
        )

        logger.info(f"{SERVER_NAME} v{VERSION} started")
        buf = b""
        while self.running:
            try:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                buf += chunk
                while True:
                    if b"Content-Length:" not in buf:
                        break
                    header_end = buf.find(b"\r\n\r\n")
                    if header_end == -1:
                        break
                    header = buf[:header_end].decode("utf-8")
                    length = 0
                    for line in header.split("\r\n"):
                        if line.startswith("Content-Length:"):
                            length = int(line.split(":")[1].strip())
                    body_start = header_end + 4
                    if len(buf) < body_start + length:
                        break
                    body = buf[body_start : body_start + length].decode("utf-8")
                    buf = buf[body_start + length :]
                    req = json.loads(body)
                    resp = await self.handle(req)
                    if resp:
                        data = json.dumps(resp).encode("utf-8")
                        frame = f"Content-Length: {len(data)}\r\n\r\n".encode("utf-8")
                        sys.stdout.buffer.write(frame + data)
                        sys.stdout.buffer.flush()
            except Exception as e:
                logger.error(f"Error: {e}")
                break


if __name__ == "__main__":
    asyncio.run(MCPServer().run())
