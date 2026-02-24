#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    LEVIATHAN VS - Frida Engine v4.0
    Complete Frida integration for LDPlayer

    Handles: server management, process attachment, spawning, hooking,
    class enumeration, method interception, memory scanning,
    SSL pinning bypass, and advanced instrumentation.

    v4.0 Changes:
        - Retry logic for server operations
        - Message buffer size limit from config
        - Scripts dir resolution relative to module
        - Session event handlers (detached callback)
        - Improved error messages
================================================================================
"""

import json
import logging
import os
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("leviathan.frida")

# Try to import frida - will be None if not installed
try:
    import frida

    FRIDA_AVAILABLE = True
except ImportError:
    frida = None
    FRIDA_AVAILABLE = False

# Module directory for resolving relative paths
_MODULE_DIR = Path(__file__).resolve().parent


class FridaEngine:
    """Complete Frida instrumentation engine for Android."""

    def __init__(self, adb_manager=None, config: Optional[Dict] = None):
        self.adb = adb_manager
        self.config = config or {}
        self._device = None
        self._session = None
        self._scripts: Dict[str, Any] = {}
        self._messages: List[Dict] = []
        self._message_handlers: Dict[str, Callable] = {}
        self._server_pid: Optional[int] = None
        self._on_detach_callback: Optional[Callable] = None

        # Config defaults
        self.server_path = self.config.get(
            "server_path", "/data/local/tmp/frida-server"
        )
        self.server_name = self.config.get("server_name", "frida-server")
        self.default_timeout = self.config.get("default_timeout", 10)
        self.enable_jit = self.config.get("enable_jit", True)
        self.message_buffer_size = self.config.get("message_buffer_size", 10000)
        self.port = self.config.get("port", 27042)

        # Resolve scripts_dir relative to module if not absolute
        scripts_dir_cfg = self.config.get("scripts_dir", "frida_scripts")
        scripts_path = Path(scripts_dir_cfg)
        if not scripts_path.is_absolute():
            scripts_path = _MODULE_DIR / scripts_path
        self.scripts_dir = scripts_path

    # ─────────────────────────────────────────────────────────────────────
    # FRIDA SERVER MANAGEMENT
    # ─────────────────────────────────────────────────────────────────────

    def check_frida_installed(self) -> Dict[str, Any]:
        """Verifica se Frida esta instalado no host."""
        return {
            "frida_module": FRIDA_AVAILABLE,
            "frida_version": frida.__version__ if FRIDA_AVAILABLE else None,
        }

    def is_server_running(self, device: Optional[str] = None) -> bool:
        """Verifica se frida-server esta rodando no device."""
        if not self.adb:
            return False
        rc, out, _ = self.adb.shell(f"ps | grep {self.server_name}", device)
        if rc == 0 and self.server_name in out:
            return True
        rc, out, _ = self.adb.shell(f"ps -A | grep {self.server_name}", device)
        return rc == 0 and self.server_name in out

    def push_server(
        self, local_path: str, device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Envia frida-server para o device."""
        if not self.adb:
            return {"success": False, "error": "ADB not configured"}

        result = self.adb.push(local_path, self.server_path, device)
        if result["success"]:
            self.adb.shell(f"chmod 755 {self.server_path}", device)
        return result

    def start_server(
        self, device: Optional[str] = None, port: int = 27042
    ) -> Dict[str, Any]:
        """Inicia frida-server no device."""
        if not self.adb:
            return {"success": False, "error": "ADB not configured"}

        if self.is_server_running(device):
            return {"success": True, "message": "Server already running"}

        # Kill any existing instance
        self.adb.shell(f"pkill -f {self.server_name}", device)
        time.sleep(0.5)

        # Start server
        cmd = f"{self.server_path} -l 0.0.0.0:{port} -D"
        self.adb.shell(f"nohup {cmd} &", device)

        # Wait for server to start
        time.sleep(2)
        running = self.is_server_running(device)

        return {
            "success": running,
            "port": port,
            "path": self.server_path,
            "message": "Server started" if running else "Failed to start server",
        }

    def stop_server(self, device: Optional[str] = None) -> Dict[str, Any]:
        """Para frida-server no device."""
        if not self.adb:
            return {"success": False, "error": "ADB not configured"}

        self.adb.shell(f"pkill -f {self.server_name}", device)
        self.adb.shell(f"killall {self.server_name}", device)
        time.sleep(0.5)
        return {"success": not self.is_server_running(device)}

    def restart_server(
        self, device: Optional[str] = None, port: int = 27042
    ) -> Dict[str, Any]:
        """Reinicia frida-server."""
        self.stop_server(device)
        time.sleep(1)
        return self.start_server(device, port)

    def get_server_info(self, device: Optional[str] = None) -> Dict[str, Any]:
        """Retorna info do frida-server."""
        if not self.adb:
            return {"error": "ADB not configured"}

        running = self.is_server_running(device)
        exists = self.adb.file_exists(self.server_path, device)

        info = {
            "installed": exists,
            "running": running,
            "path": self.server_path,
        }

        if exists:
            size = self.adb.get_file_size(self.server_path, device)
            info["size_bytes"] = size

        if running:
            rc, out, _ = self.adb.shell(f"ps -A | grep {self.server_name}", device)
            if rc == 0:
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 2:
                        info["pid"] = parts[1]
                        break

        return info

    # ─────────────────────────────────────────────────────────────────────
    # DEVICE & SESSION
    # ─────────────────────────────────────────────────────────────────────

    def get_device(
        self,
        device_id: Optional[str] = None,
        host: str = "127.0.0.1",
        port: int = 27042,
    ) -> Any:
        """Obtem device Frida."""
        if not FRIDA_AVAILABLE:
            raise RuntimeError(
                "Frida not installed. Run: pip install frida frida-tools"
            )

        if device_id:
            self._device = frida.get_device(device_id)
        else:
            try:
                mgr = frida.get_device_manager()
                self._device = mgr.add_remote_device(f"{host}:{port}")
            except Exception:
                try:
                    self._device = frida.get_usb_device(timeout=self.default_timeout)
                except Exception:
                    self._device = frida.get_remote_device()

        return self._device

    def list_devices(self) -> List[Dict[str, str]]:
        """Lista devices Frida disponiveis."""
        if not FRIDA_AVAILABLE:
            return [{"error": "Frida not installed"}]

        devices = []
        for d in frida.enumerate_devices():
            devices.append(
                {
                    "id": d.id,
                    "name": d.name,
                    "type": str(d.type),
                }
            )
        return devices

    def list_processes(self, device_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Lista processos no device."""
        dev = self._device or self.get_device(device_id)
        processes = []
        for p in dev.enumerate_processes():
            processes.append(
                {
                    "pid": p.pid,
                    "name": p.name,
                }
            )
        return processes

    def list_applications(
        self, device_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Lista aplicacoes instaladas."""
        dev = self._device or self.get_device(device_id)
        apps = []
        for a in dev.enumerate_applications():
            apps.append(
                {
                    "identifier": a.identifier,
                    "name": a.name,
                    "pid": a.pid,
                }
            )
        return apps

    def find_process(self, name_or_package: str) -> Optional[Dict[str, Any]]:
        """Encontra processo por nome ou package."""
        for p in self.list_processes():
            if name_or_package.lower() in p["name"].lower():
                return p
        return None

    # ─────────────────────────────────────────────────────────────────────
    # ATTACH / SPAWN
    # ─────────────────────────────────────────────────────────────────────

    def _on_session_detached(self, reason: str, crash):
        """Handle session detach events."""
        logger.warning(f"Session detached: reason={reason}")
        self._session = None
        # Unload all scripts as they're now invalid
        self._scripts.clear()
        if self._on_detach_callback:
            try:
                self._on_detach_callback(reason, crash)
            except Exception as e:
                logger.warning(f"Detach callback error: {e}")

    def attach(self, target: Any, device_id: Optional[str] = None) -> Dict[str, Any]:
        """Attach ao processo (PID ou nome)."""
        dev = self._device or self.get_device(device_id)
        try:
            self._session = dev.attach(target)
            self._session.on("detached", self._on_session_detached)
            if self.enable_jit:
                self._session.enable_jit()
            return {
                "success": True,
                "target": str(target),
                "pid": (
                    self._session._impl.pid
                    if hasattr(self._session, "_impl")
                    else target
                ),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def spawn(
        self, package: str, device_id: Optional[str] = None, paused: bool = True
    ) -> Dict[str, Any]:
        """Spawn processo."""
        dev = self._device or self.get_device(device_id)
        try:
            pid = dev.spawn([package])
            self._session = dev.attach(pid)
            self._session.on("detached", self._on_session_detached)
            if self.enable_jit:
                self._session.enable_jit()
            if not paused:
                dev.resume(pid)
            return {"success": True, "pid": pid, "package": package, "paused": paused}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def resume(self, pid: int) -> Dict[str, Any]:
        """Resume processo pausado."""
        dev = self._device or self.get_device()
        try:
            dev.resume(pid)
            return {"success": True, "pid": pid}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def kill_process(self, pid: int) -> Dict[str, Any]:
        """Mata processo."""
        dev = self._device or self.get_device()
        try:
            dev.kill(pid)
            return {"success": True, "pid": pid}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def detach(self) -> Dict[str, Any]:
        """Desconecta da sessao atual."""
        if self._session:
            try:
                self._session.detach()
                self._session = None
                return {"success": True}
            except Exception as e:
                return {"success": False, "error": str(e)}
        return {"success": False, "error": "No active session"}

    # ─────────────────────────────────────────────────────────────────────
    # SCRIPT INJECTION
    # ─────────────────────────────────────────────────────────────────────

    def _on_message(self, script_name: str, message: Dict, data: Any):
        """Handler padrao de mensagens com buffer size limit."""
        entry = {
            "script": script_name,
            "type": message.get("type"),
            "payload": message.get("payload"),
            "timestamp": time.time(),
        }
        self._messages.append(entry)

        # Enforce buffer size limit
        if len(self._messages) > self.message_buffer_size:
            self._messages = self._messages[-self.message_buffer_size :]

        # Call custom handler if registered
        if script_name in self._message_handlers:
            try:
                self._message_handlers[script_name](message, data)
            except Exception as e:
                logger.warning(f"Message handler error for {script_name}: {e}")

        if message["type"] == "send":
            logger.info(f"[{script_name}] {message.get('payload')}")
        elif message["type"] == "error":
            logger.error(
                f"[{script_name}] {message.get('stack', message.get('description'))}"
            )

    def inject_script(
        self, source: str, name: str = "default", on_message: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """Injeta script Frida."""
        if not self._session:
            return {
                "success": False,
                "error": "No active session. Call attach() or spawn() first.",
            }

        try:
            script = self._session.create_script(source)

            if on_message:
                self._message_handlers[name] = on_message

            script.on("message", lambda msg, data: self._on_message(name, msg, data))
            script.load()

            self._scripts[name] = script
            return {"success": True, "name": name}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def inject_script_file(
        self,
        file_path: str,
        name: Optional[str] = None,
        on_message: Optional[Callable] = None,
    ) -> Dict[str, Any]:
        """Injeta script de arquivo."""
        path = Path(file_path)
        if not path.exists():
            # Try scripts dir
            path = self.scripts_dir / file_path
        if not path.exists():
            return {"success": False, "error": f"Script not found: {file_path}"}

        with open(path, "r", encoding="utf-8") as f:
            source = f.read()

        script_name = name or path.stem
        return self.inject_script(source, script_name, on_message)

    def unload_script(self, name: str = "default") -> Dict[str, Any]:
        """Descarrega script."""
        if name in self._scripts:
            try:
                self._scripts[name].unload()
                del self._scripts[name]
                return {"success": True, "name": name}
            except Exception as e:
                return {"success": False, "error": str(e)}
        return {"success": False, "error": f"Script not found: {name}"}

    def unload_all_scripts(self) -> Dict[str, Any]:
        """Descarrega todos os scripts."""
        results = []
        for name in list(self._scripts.keys()):
            r = self.unload_script(name)
            results.append({"name": name, **r})
        return {"success": True, "results": results}

    def call_export(self, name: str, method: str, *args) -> Any:
        """Chama funcao exportada do script."""
        if name not in self._scripts:
            return {"error": f"Script not found: {name}"}
        try:
            exports = self._scripts[name].exports_sync
            func = getattr(exports, method)
            return func(*args)
        except Exception as e:
            return {"error": str(e)}

    def get_messages(
        self, script_name: Optional[str] = None, limit: int = 100
    ) -> List[Dict]:
        """Retorna mensagens recebidas."""
        msgs = self._messages
        if script_name:
            msgs = [m for m in msgs if m["script"] == script_name]
        return msgs[-limit:]

    def clear_messages(self):
        """Limpa buffer de mensagens."""
        self._messages.clear()

    # ─────────────────────────────────────────────────────────────────────
    # JAVA / ANDROID HOOKING
    # ─────────────────────────────────────────────────────────────────────

    def enumerate_classes(self, filter_str: str = "") -> Dict[str, Any]:
        """Enumera classes Java carregadas."""
        script_src = (
            """
        Java.perform(function() {
            var classes = Java.enumerateLoadedClassesSync();
            var filter = '%s';
            if (filter) {
                classes = classes.filter(function(c) {
                    return c.toLowerCase().indexOf(filter.toLowerCase()) !== -1;
                });
            }
            send({type: 'classes', data: classes, total: classes.length});
        });
        """
            % filter_str
        )

        result = {"classes": [], "total": 0}

        def handler(msg, data):
            if msg["type"] == "send" and isinstance(msg.get("payload"), dict):
                result["classes"] = msg["payload"].get("data", [])
                result["total"] = msg["payload"].get("total", 0)

        r = self.inject_script(script_src, "_enum_classes", handler)
        if not r["success"]:
            return r
        time.sleep(1)
        self.unload_script("_enum_classes")

        # Also check messages
        for m in reversed(self._messages):
            if m["script"] == "_enum_classes" and isinstance(m.get("payload"), dict):
                result["classes"] = m["payload"].get("data", [])
                result["total"] = m["payload"].get("total", 0)
                break

        return result

    def enumerate_methods(self, class_name: str) -> Dict[str, Any]:
        """Enumera metodos de uma classe Java."""
        script_src = """
        Java.perform(function() {
            try {
                var cls = Java.use('%s');
                var methods = cls.class.getDeclaredMethods();
                var result = [];
                for (var i = 0; i < methods.length; i++) {
                    result.push({
                        name: methods[i].getName(),
                        return_type: methods[i].getReturnType().getName(),
                        params: methods[i].getParameterTypes().map(function(p) { return p.getName(); }),
                        modifiers: methods[i].getModifiers()
                    });
                }
                var fields = cls.class.getDeclaredFields();
                var fieldList = [];
                for (var j = 0; j < fields.length; j++) {
                    fieldList.push({
                        name: fields[j].getName(),
                        type: fields[j].getType().getName(),
                        modifiers: fields[j].getModifiers()
                    });
                }
                send({type: 'methods', methods: result, fields: fieldList, class: '%s'});
            } catch(e) {
                send({type: 'error', message: e.toString()});
            }
        });
        """ % (
            class_name,
            class_name,
        )

        result = {"methods": [], "fields": [], "class": class_name}

        def handler(msg, data):
            if msg["type"] == "send" and isinstance(msg.get("payload"), dict):
                result["methods"] = msg["payload"].get("methods", [])
                result["fields"] = msg["payload"].get("fields", [])

        r = self.inject_script(script_src, "_enum_methods", handler)
        if not r["success"]:
            return r
        time.sleep(1)
        self.unload_script("_enum_methods")

        for m in reversed(self._messages):
            if m["script"] == "_enum_methods" and isinstance(m.get("payload"), dict):
                result["methods"] = m["payload"].get("methods", [])
                result["fields"] = m["payload"].get("fields", [])
                break

        return result

    def hook_method(
        self,
        class_name: str,
        method_name: str,
        on_enter: str = "",
        on_leave: str = "",
        script_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Hook em metodo Java especifico."""
        on_enter_code = (
            on_enter
            or """
            console.log('[HOOK] ' + '%s.%s' + ' called');
            console.log('[HOOK] Args: ' + JSON.stringify(arguments));
            send({type: 'hook', class: '%s', method: '%s', event: 'enter', args: Array.prototype.slice.call(arguments).map(String)});
        """
            % (class_name, method_name, class_name, method_name)
        )

        on_leave_code = (
            on_leave
            or """
            console.log('[HOOK] ' + '%s.%s' + ' returned: ' + retval);
            send({type: 'hook', class: '%s', method: '%s', event: 'leave', retval: String(retval)});
        """
            % (class_name, method_name, class_name, method_name)
        )

        script_src = """
        Java.perform(function() {
            try {
                var cls = Java.use('%s');
                var overloads = cls['%s'].overloads;

                overloads.forEach(function(overload) {
                    overload.implementation = function() {
                        %s
                        var retval = overload.apply(this, arguments);
                        %s
                        return retval;
                    };
                });

                send({type: 'hook_installed', class: '%s', method: '%s', overloads: overloads.length});
            } catch(e) {
                send({type: 'error', message: 'Hook failed: ' + e.toString()});
            }
        });
        """ % (
            class_name,
            method_name,
            on_enter_code,
            on_leave_code,
            class_name,
            method_name,
        )

        name = script_name or f"hook_{class_name}_{method_name}".replace(".", "_")
        return self.inject_script(script_src, name)

    def hook_class(
        self, class_name: str, script_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Hook em TODOS os metodos de uma classe."""
        script_src = (
            """
        Java.perform(function() {
            try {
                var className = '%s';
                var cls = Java.use(className);
                var methods = cls.class.getDeclaredMethods();
                var hooked = 0;

                methods.forEach(function(method) {
                    var methodName = method.getName();
                    try {
                        var overloads = cls[methodName].overloads;
                        overloads.forEach(function(overload) {
                            overload.implementation = function() {
                                var args = Array.prototype.slice.call(arguments).map(function(a) {
                                    try { return String(a); } catch(e) { return '<unprintable>'; }
                                });
                                send({
                                    type: 'class_hook',
                                    class: className,
                                    method: methodName,
                                    event: 'enter',
                                    args: args
                                });
                                var retval = overload.apply(this, arguments);
                                send({
                                    type: 'class_hook',
                                    class: className,
                                    method: methodName,
                                    event: 'leave',
                                    retval: String(retval)
                                });
                                return retval;
                            };
                        });
                        hooked++;
                    } catch(e) {
                        // Skip methods that can't be hooked
                    }
                });

                send({type: 'class_hooked', class: className, methods_hooked: hooked, total_methods: methods.length});
            } catch(e) {
                send({type: 'error', message: 'Class hook failed: ' + e.toString()});
            }
        });
        """
            % class_name
        )

        name = script_name or f"hook_class_{class_name}".replace(".", "_")
        return self.inject_script(script_src, name)

    def hook_constructor(
        self, class_name: str, script_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Hook no construtor de uma classe."""
        script_src = """
        Java.perform(function() {
            try {
                var cls = Java.use('%s');
                cls.$init.overloads.forEach(function(overload) {
                    overload.implementation = function() {
                        var args = Array.prototype.slice.call(arguments).map(String);
                        send({
                            type: 'constructor',
                            class: '%s',
                            args: args
                        });
                        return overload.apply(this, arguments);
                    };
                });
                send({type: 'constructor_hooked', class: '%s'});
            } catch(e) {
                send({type: 'error', message: e.toString()});
            }
        });
        """ % (
            class_name,
            class_name,
            class_name,
        )

        name = script_name or f"hook_ctor_{class_name}".replace(".", "_")
        return self.inject_script(script_src, name)

    def hook_native(
        self,
        module_name: str,
        function_name: str,
        on_enter: str = "",
        on_leave: str = "",
        script_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Hook em funcao nativa (C/C++)."""
        on_enter_code = (
            on_enter
            or """
            send({
                type: 'native_hook',
                module: '%s',
                function: '%s',
                event: 'enter',
                args: [this.context.x0, this.context.x1, this.context.x2, this.context.x3].map(String)
            });
        """
            % (module_name, function_name)
        )

        on_leave_code = (
            on_leave
            or """
            send({
                type: 'native_hook',
                module: '%s',
                function: '%s',
                event: 'leave',
                retval: retval.toString()
            });
        """
            % (module_name, function_name)
        )

        script_src = """
        var addr = Module.findExportByName('%s', '%s');
        if (addr) {
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    %s
                },
                onLeave: function(retval) {
                    %s
                }
            });
            send({type: 'native_hooked', module: '%s', function: '%s', address: addr.toString()});
        } else {
            send({type: 'error', message: 'Function not found: %s!%s'});
        }
        """ % (
            module_name,
            function_name,
            on_enter_code,
            on_leave_code,
            module_name,
            function_name,
            module_name,
            function_name,
        )

        name = script_name or f"native_{module_name}_{function_name}"
        return self.inject_script(script_src, name)

    def hook_native_address(
        self,
        address: str,
        on_enter: str = "",
        on_leave: str = "",
        script_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Hook em endereco de memoria especifico."""
        on_enter_code = (
            on_enter
            or """
            send({type: 'addr_hook', address: '%s', event: 'enter'});
        """
            % address
        )

        on_leave_code = (
            on_leave
            or """
            send({type: 'addr_hook', address: '%s', event: 'leave', retval: retval.toString()});
        """
            % address
        )

        script_src = """
        var addr = ptr('%s');
        Interceptor.attach(addr, {
            onEnter: function(args) {
                %s
            },
            onLeave: function(retval) {
                %s
            }
        });
        send({type: 'address_hooked', address: '%s'});
        """ % (
            address,
            on_enter_code,
            on_leave_code,
            address,
        )

        name = script_name or f"addr_{address}"
        return self.inject_script(script_src, name)

    def replace_method_return(
        self,
        class_name: str,
        method_name: str,
        return_value: str,
        script_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Substitui retorno de um metodo Java."""
        script_src = """
        Java.perform(function() {
            var cls = Java.use('%s');
            cls['%s'].overloads.forEach(function(overload) {
                overload.implementation = function() {
                    send({type: 'replaced', class: '%s', method: '%s', original_args: Array.prototype.slice.call(arguments).map(String)});
                    return %s;
                };
            });
            send({type: 'method_replaced', class: '%s', method: '%s', new_return: '%s'});
        });
        """ % (
            class_name,
            method_name,
            class_name,
            method_name,
            return_value,
            class_name,
            method_name,
            return_value,
        )

        name = script_name or f"replace_{class_name}_{method_name}".replace(".", "_")
        return self.inject_script(script_src, name)

    # ─────────────────────────────────────────────────────────────────────
    # MEMORY OPERATIONS
    # ─────────────────────────────────────────────────────────────────────

    def memory_scan(
        self,
        pattern: str,
        module_name: Optional[str] = None,
        script_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Scan de memoria por pattern."""
        if module_name:
            scan_code = """
            var mod = Process.findModuleByName('%s');
            if (mod) {
                Memory.scan(mod.base, mod.size, '%s', {
                    onMatch: function(address, size) {
                        send({type: 'memory_match', address: address.toString(), size: size, module: '%s'});
                    },
                    onComplete: function() {
                        send({type: 'scan_complete', module: '%s'});
                    }
                });
            }
            """ % (
                module_name,
                pattern,
                module_name,
                module_name,
            )
        else:
            scan_code = (
                """
            Process.enumerateModules().forEach(function(mod) {
                try {
                    Memory.scan(mod.base, mod.size, '%s', {
                        onMatch: function(address, size) {
                            send({type: 'memory_match', address: address.toString(), size: size, module: mod.name});
                        },
                        onComplete: function() {}
                    });
                } catch(e) {}
            });
            send({type: 'scan_complete'});
            """
                % pattern
            )

        name = script_name or f"memscan_{int(time.time())}"
        return self.inject_script(scan_code, name)

    def read_memory(self, address: str, size: int) -> Dict[str, Any]:
        """Le memoria em endereco."""
        script_src = """
        var addr = ptr('%s');
        var buf = Memory.readByteArray(addr, %d);
        send({type: 'memory_read', address: '%s', size: %d}, buf);
        """ % (
            address,
            size,
            address,
            size,
        )

        return self.inject_script(script_src, f"memread_{address}")

    def write_memory(self, address: str, data: List[int]) -> Dict[str, Any]:
        """Escreve na memoria."""
        data_str = ", ".join([str(b) for b in data])
        script_src = """
        var addr = ptr('%s');
        Memory.writeByteArray(addr, [%s]);
        send({type: 'memory_written', address: '%s', bytes: %d});
        """ % (
            address,
            data_str,
            address,
            len(data),
        )

        return self.inject_script(script_src, f"memwrite_{address}")

    def enumerate_modules(self) -> Dict[str, Any]:
        """Enumera modulos carregados."""
        script_src = """
        var modules = Process.enumerateModules();
        var result = modules.map(function(m) {
            return {
                name: m.name,
                base: m.base.toString(),
                size: m.size,
                path: m.path
            };
        });
        send({type: 'modules', data: result, total: result.length});
        """
        return self.inject_script(script_src, "_enum_modules")

    def enumerate_exports(self, module_name: str) -> Dict[str, Any]:
        """Enumera exports de um modulo."""
        script_src = """
        var exports = Module.enumerateExports('%s');
        var result = exports.map(function(e) {
            return {name: e.name, type: e.type, address: e.address.toString()};
        });
        send({type: 'exports', module: '%s', data: result, total: result.length});
        """ % (
            module_name,
            module_name,
        )

        return self.inject_script(script_src, f"_exports_{module_name}")

    def enumerate_imports(self, module_name: str) -> Dict[str, Any]:
        """Enumera imports de um modulo."""
        script_src = """
        var imports = Module.enumerateImports('%s');
        var result = imports.map(function(i) {
            return {name: i.name, type: i.type, module: i.module, address: i.address ? i.address.toString() : null};
        });
        send({type: 'imports', module: '%s', data: result, total: result.length});
        """ % (
            module_name,
            module_name,
        )

        return self.inject_script(script_src, f"_imports_{module_name}")

    # ─────────────────────────────────────────────────────────────────────
    # DYNAMIC CLASS LOADING & REFLECTION
    # ─────────────────────────────────────────────────────────────────────

    def find_class(self, pattern: str) -> Dict[str, Any]:
        """Busca classes por pattern."""
        return self.enumerate_classes(pattern)

    def get_class_info(self, class_name: str) -> Dict[str, Any]:
        """Retorna info completa de uma classe."""
        script_src = """
        Java.perform(function() {
            try {
                var cls = Java.use('%s');
                var clsObj = cls.class;

                var methods = clsObj.getDeclaredMethods().map(function(m) {
                    return {
                        name: m.getName(),
                        return_type: m.getReturnType().getName(),
                        params: m.getParameterTypes().map(function(p) { return p.getName(); }),
                        is_static: (m.getModifiers() & 0x8) !== 0,
                        is_public: (m.getModifiers() & 0x1) !== 0,
                        is_private: (m.getModifiers() & 0x2) !== 0,
                        is_native: (m.getModifiers() & 0x100) !== 0,
                    };
                });

                var fields = clsObj.getDeclaredFields().map(function(f) {
                    return {
                        name: f.getName(),
                        type: f.getType().getName(),
                        is_static: (f.getModifiers() & 0x8) !== 0,
                        is_final: (f.getModifiers() & 0x10) !== 0,
                    };
                });

                var constructors = clsObj.getDeclaredConstructors().map(function(c) {
                    return {
                        params: c.getParameterTypes().map(function(p) { return p.getName(); })
                    };
                });

                var interfaces = clsObj.getInterfaces().map(function(i) { return i.getName(); });
                var superclass = clsObj.getSuperclass() ? clsObj.getSuperclass().getName() : null;

                send({
                    type: 'class_info',
                    class: '%s',
                    superclass: superclass,
                    interfaces: interfaces,
                    methods: methods,
                    fields: fields,
                    constructors: constructors
                });
            } catch(e) {
                send({type: 'error', message: e.toString()});
            }
        });
        """ % (
            class_name,
            class_name,
        )

        return self.inject_script(
            script_src, f"_classinfo_{class_name.replace('.', '_')}"
        )

    def get_field_value(
        self, class_name: str, field_name: str, is_static: bool = True
    ) -> Dict[str, Any]:
        """Le valor de um campo."""
        if is_static:
            script_src = """
            Java.perform(function() {
                var cls = Java.use('%s');
                var field = cls.class.getDeclaredField('%s');
                field.setAccessible(true);
                var value = field.get(null);
                send({type: 'field_value', class: '%s', field: '%s', value: String(value)});
            });
            """ % (
                class_name,
                field_name,
                class_name,
                field_name,
            )
        else:
            script_src = """
            Java.perform(function() {
                Java.choose('%s', {
                    onMatch: function(instance) {
                        var field = instance.class.getDeclaredField('%s');
                        field.setAccessible(true);
                        var value = field.get(instance);
                        send({type: 'field_value', class: '%s', field: '%s', value: String(value), instance: instance.toString()});
                    },
                    onComplete: function() {
                        send({type: 'field_scan_complete'});
                    }
                });
            });
            """ % (
                class_name,
                field_name,
                class_name,
                field_name,
            )

        return self.inject_script(
            script_src, f"_field_{class_name}_{field_name}".replace(".", "_")
        )

    def set_field_value(
        self, class_name: str, field_name: str, value: str, is_static: bool = True
    ) -> Dict[str, Any]:
        """Define valor de um campo."""
        if is_static:
            script_src = """
            Java.perform(function() {
                var cls = Java.use('%s');
                var field = cls.class.getDeclaredField('%s');
                field.setAccessible(true);
                field.set(null, %s);
                send({type: 'field_set', class: '%s', field: '%s', value: '%s'});
            });
            """ % (
                class_name,
                field_name,
                value,
                class_name,
                field_name,
                value,
            )
        else:
            script_src = """
            Java.perform(function() {
                Java.choose('%s', {
                    onMatch: function(instance) {
                        var field = instance.class.getDeclaredField('%s');
                        field.setAccessible(true);
                        field.set(instance, %s);
                        send({type: 'field_set', class: '%s', field: '%s', value: '%s'});
                    },
                    onComplete: function() {}
                });
            });
            """ % (
                class_name,
                field_name,
                value,
                class_name,
                field_name,
                value,
            )

        return self.inject_script(
            script_src, f"_setfield_{class_name}_{field_name}".replace(".", "_")
        )

    def call_method(
        self,
        class_name: str,
        method_name: str,
        args: List[str] = None,
        is_static: bool = True,
    ) -> Dict[str, Any]:
        """Chama metodo de uma classe."""
        args_str = ", ".join(args) if args else ""

        if is_static:
            script_src = """
            Java.perform(function() {
                var cls = Java.use('%s');
                var result = cls['%s'](%s);
                send({type: 'call_result', class: '%s', method: '%s', result: String(result)});
            });
            """ % (
                class_name,
                method_name,
                args_str,
                class_name,
                method_name,
            )
        else:
            script_src = """
            Java.perform(function() {
                Java.choose('%s', {
                    onMatch: function(instance) {
                        var result = instance['%s'](%s);
                        send({type: 'call_result', class: '%s', method: '%s', result: String(result)});
                    },
                    onComplete: function() {}
                });
            });
            """ % (
                class_name,
                method_name,
                args_str,
                class_name,
                method_name,
            )

        return self.inject_script(
            script_src, f"_call_{class_name}_{method_name}".replace(".", "_")
        )

    def find_instances(self, class_name: str) -> Dict[str, Any]:
        """Encontra instancias vivas de uma classe na heap."""
        script_src = """
        Java.perform(function() {
            var instances = [];
            Java.choose('%s', {
                onMatch: function(instance) {
                    instances.push({
                        toString: instance.toString(),
                        hashCode: instance.hashCode()
                    });
                },
                onComplete: function() {
                    send({type: 'instances', class: '%s', count: instances.length, instances: instances.slice(0, 50)});
                }
            });
        });
        """ % (
            class_name,
            class_name,
        )

        return self.inject_script(
            script_src, f"_instances_{class_name.replace('.', '_')}"
        )

    # ─────────────────────────────────────────────────────────────────────
    # TRACING
    # ─────────────────────────────────────────────────────────────────────

    def trace_class(
        self,
        class_name: str,
        include_args: bool = True,
        include_return: bool = True,
        include_backtrace: bool = False,
    ) -> Dict[str, Any]:
        """Trace completo de uma classe (todos os metodos)."""
        bt_code = (
            """
                        var bt = Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new());
                        entry.backtrace = bt.toString().split('\\n').slice(0,10);
        """
            if include_backtrace
            else ""
        )

        script_src = """
        Java.perform(function() {
            var cls = Java.use('%s');
            var methods = cls.class.getDeclaredMethods();
            var hooked = 0;

            methods.forEach(function(method) {
                var methodName = method.getName();
                try {
                    cls[methodName].overloads.forEach(function(overload) {
                        overload.implementation = function() {
                            var entry = {
                                type: 'trace',
                                class: '%s',
                                method: methodName,
                                timestamp: Date.now()
                            };
                            %s
                            %s
                            var retval = overload.apply(this, arguments);
                            %s
                            send(entry);
                            return retval;
                        };
                    });
                    hooked++;
                } catch(e) {}
            });

            send({type: 'trace_installed', class: '%s', methods_hooked: hooked});
        });
        """ % (
            class_name,
            class_name,
            (
                "entry.args = Array.prototype.slice.call(arguments).map(function(a) { try { return String(a); } catch(e) { return '<err>'; } });"
                if include_args
                else ""
            ),
            bt_code,
            "entry.retval = String(retval);" if include_return else "",
            class_name,
        )

        return self.inject_script(script_src, f"trace_{class_name.replace('.', '_')}")

    def trace_native_calls(
        self, module_name: str, function_pattern: str = ""
    ) -> Dict[str, Any]:
        """Trace de chamadas nativas de um modulo."""
        script_src = """
        var mod = Process.findModuleByName('%s');
        if (mod) {
            var exports = mod.enumerateExports();
            var pattern = '%s';
            var hooked = 0;

            exports.forEach(function(exp) {
                if (exp.type === 'function') {
                    if (!pattern || exp.name.indexOf(pattern) !== -1) {
                        try {
                            Interceptor.attach(exp.address, {
                                onEnter: function(args) {
                                    send({
                                        type: 'native_trace',
                                        module: '%s',
                                        function: exp.name,
                                        event: 'enter',
                                        address: exp.address.toString()
                                    });
                                },
                                onLeave: function(retval) {
                                    send({
                                        type: 'native_trace',
                                        module: '%s',
                                        function: exp.name,
                                        event: 'leave',
                                        retval: retval.toString()
                                    });
                                }
                            });
                            hooked++;
                        } catch(e) {}
                    }
                }
            });

            send({type: 'native_trace_installed', module: '%s', hooked: hooked});
        } else {
            send({type: 'error', message: 'Module not found: %s'});
        }
        """ % (
            module_name,
            function_pattern,
            module_name,
            module_name,
            module_name,
            module_name,
        )

        return self.inject_script(script_src, f"ntrace_{module_name}")

    # ─────────────────────────────────────────────────────────────────────
    # UTILITY SCRIPTS
    # ─────────────────────────────────────────────────────────────────────

    def get_android_info(self) -> Dict[str, Any]:
        """Coleta info do Android via Frida."""
        script_src = """
        Java.perform(function() {
            var Build = Java.use('android.os.Build');
            var VERSION = Java.use('android.os.Build$VERSION');

            send({
                type: 'android_info',
                brand: Build.BRAND.value,
                model: Build.MODEL.value,
                manufacturer: Build.MANUFACTURER.value,
                device: Build.DEVICE.value,
                product: Build.PRODUCT.value,
                hardware: Build.HARDWARE.value,
                board: Build.BOARD.value,
                fingerprint: Build.FINGERPRINT.value,
                sdk_int: VERSION.SDK_INT.value,
                release: VERSION.RELEASE.value,
                codename: VERSION.CODENAME.value,
                security_patch: VERSION.SECURITY_PATCH ? VERSION.SECURITY_PATCH.value : 'N/A'
            });
        });
        """
        return self.inject_script(script_src, "_android_info")

    def intercept_crypto(self) -> Dict[str, Any]:
        """Intercepta operacoes de criptografia."""
        script_src = """
        Java.perform(function() {
            // Cipher
            var Cipher = Java.use('javax.crypto.Cipher');
            Cipher.getInstance.overloads.forEach(function(overload) {
                overload.implementation = function() {
                    var result = overload.apply(this, arguments);
                    send({type: 'crypto', operation: 'Cipher.getInstance', args: Array.prototype.slice.call(arguments).map(String)});
                    return result;
                };
            });

            Cipher.doFinal.overloads.forEach(function(overload) {
                overload.implementation = function() {
                    var result = overload.apply(this, arguments);
                    var inputHex = '';
                    var outputHex = '';
                    try {
                        if (arguments.length > 0 && arguments[0]) {
                            var arr = Java.array('byte', arguments[0]);
                            for (var i = 0; i < Math.min(arr.length, 64); i++) {
                                inputHex += ('0' + (arr[i] & 0xFF).toString(16)).slice(-2);
                            }
                        }
                        if (result) {
                            var out = Java.array('byte', result);
                            for (var j = 0; j < Math.min(out.length, 64); j++) {
                                outputHex += ('0' + (out[j] & 0xFF).toString(16)).slice(-2);
                            }
                        }
                    } catch(e) {}
                    send({type: 'crypto', operation: 'Cipher.doFinal', input: inputHex, output: outputHex, algorithm: this.getAlgorithm()});
                    return result;
                };
            });

            // SecretKeySpec
            var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
            SecretKeySpec.$init.overloads.forEach(function(overload) {
                overload.implementation = function() {
                    var keyHex = '';
                    try {
                        var keyBytes = Java.array('byte', arguments[0]);
                        for (var i = 0; i < keyBytes.length; i++) {
                            keyHex += ('0' + (keyBytes[i] & 0xFF).toString(16)).slice(-2);
                        }
                    } catch(e) {}
                    send({type: 'crypto', operation: 'SecretKeySpec', key: keyHex, algorithm: arguments.length > 1 ? String(arguments[1]) : ''});
                    return overload.apply(this, arguments);
                };
            });

            // MessageDigest (hashing)
            var MessageDigest = Java.use('java.security.MessageDigest');
            MessageDigest.getInstance.overloads.forEach(function(overload) {
                overload.implementation = function() {
                    send({type: 'crypto', operation: 'MessageDigest.getInstance', algorithm: String(arguments[0])});
                    return overload.apply(this, arguments);
                };
            });

            send({type: 'crypto_hooks_installed'});
        });
        """
        return self.inject_script(script_src, "crypto_intercept")

    def intercept_http(self) -> Dict[str, Any]:
        """Intercepta requisicoes HTTP."""
        script_src = """
        Java.perform(function() {
            // OkHttp3
            try {
                var OkHttpClient = Java.use('okhttp3.OkHttpClient');
                var Request = Java.use('okhttp3.Request');
                var RealCall = Java.use('okhttp3.internal.connection.RealCall');

                if (RealCall.execute) {
                    RealCall.execute.implementation = function() {
                        var request = this.request();
                        send({
                            type: 'http',
                            library: 'okhttp3',
                            url: request.url().toString(),
                            method: request.method(),
                            headers: request.headers().toString()
                        });
                        return this.execute.apply(this, arguments);
                    };
                }
            } catch(e) {}

            // HttpURLConnection
            try {
                var URL = Java.use('java.net.URL');
                URL.openConnection.overloads.forEach(function(overload) {
                    overload.implementation = function() {
                        send({type: 'http', library: 'URLConnection', url: this.toString()});
                        return overload.apply(this, arguments);
                    };
                });
            } catch(e) {}

            // WebView
            try {
                var WebView = Java.use('android.webkit.WebView');
                WebView.loadUrl.overloads.forEach(function(overload) {
                    overload.implementation = function() {
                        send({type: 'http', library: 'WebView', url: String(arguments[0])});
                        return overload.apply(this, arguments);
                    };
                });
            } catch(e) {}

            send({type: 'http_hooks_installed'});
        });
        """
        return self.inject_script(script_src, "http_intercept")

    def intercept_intents(self) -> Dict[str, Any]:
        """Intercepta Intents do Android."""
        script_src = """
        Java.perform(function() {
            var Activity = Java.use('android.app.Activity');
            Activity.startActivity.overloads.forEach(function(overload) {
                overload.implementation = function() {
                    var intent = arguments[0];
                    send({
                        type: 'intent',
                        action: intent.getAction() ? intent.getAction().toString() : null,
                        data: intent.getDataString() ? intent.getDataString() : null,
                        component: intent.getComponent() ? intent.getComponent().toString() : null,
                        extras: intent.getExtras() ? intent.getExtras().toString() : null,
                        flags: intent.getFlags()
                    });
                    return overload.apply(this, arguments);
                };
            });
            send({type: 'intent_hooks_installed'});
        });
        """
        return self.inject_script(script_src, "intent_intercept")

    def intercept_shared_prefs(self) -> Dict[str, Any]:
        """Intercepta SharedPreferences."""
        script_src = """
        Java.perform(function() {
            var SharedPreferencesImpl = Java.use('android.app.SharedPreferencesImpl');
            var Editor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');

            // Read
            SharedPreferencesImpl.getString.overloads.forEach(function(overload) {
                overload.implementation = function() {
                    var result = overload.apply(this, arguments);
                    send({type: 'shared_prefs', op: 'getString', key: String(arguments[0]), value: String(result)});
                    return result;
                };
            });

            SharedPreferencesImpl.getInt.overloads.forEach(function(overload) {
                overload.implementation = function() {
                    var result = overload.apply(this, arguments);
                    send({type: 'shared_prefs', op: 'getInt', key: String(arguments[0]), value: result});
                    return result;
                };
            });

            SharedPreferencesImpl.getBoolean.overloads.forEach(function(overload) {
                overload.implementation = function() {
                    var result = overload.apply(this, arguments);
                    send({type: 'shared_prefs', op: 'getBoolean', key: String(arguments[0]), value: result});
                    return result;
                };
            });

            // Write
            Editor.putString.implementation = function(key, value) {
                send({type: 'shared_prefs', op: 'putString', key: String(key), value: String(value)});
                return this.putString(key, value);
            };

            Editor.putInt.implementation = function(key, value) {
                send({type: 'shared_prefs', op: 'putInt', key: String(key), value: value});
                return this.putInt(key, value);
            };

            Editor.putBoolean.implementation = function(key, value) {
                send({type: 'shared_prefs', op: 'putBoolean', key: String(key), value: value});
                return this.putBoolean(key, value);
            };

            send({type: 'shared_prefs_hooks_installed'});
        });
        """
        return self.inject_script(script_src, "shared_prefs_intercept")

    def intercept_sqlite(self) -> Dict[str, Any]:
        """Intercepta operacoes SQLite."""
        script_src = """
        Java.perform(function() {
            var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');

            SQLiteDatabase.rawQuery.overloads.forEach(function(overload) {
                overload.implementation = function() {
                    send({type: 'sqlite', op: 'rawQuery', query: String(arguments[0])});
                    return overload.apply(this, arguments);
                };
            });

            SQLiteDatabase.execSQL.overloads.forEach(function(overload) {
                overload.implementation = function() {
                    send({type: 'sqlite', op: 'execSQL', query: String(arguments[0])});
                    return overload.apply(this, arguments);
                };
            });

            SQLiteDatabase.insert.implementation = function(table, nullColumnHack, values) {
                send({type: 'sqlite', op: 'insert', table: String(table), values: values ? values.toString() : null});
                return this.insert(table, nullColumnHack, values);
            };

            SQLiteDatabase.update.overloads.forEach(function(overload) {
                overload.implementation = function() {
                    send({type: 'sqlite', op: 'update', table: String(arguments[0])});
                    return overload.apply(this, arguments);
                };
            });

            SQLiteDatabase.delete.implementation = function(table, whereClause, whereArgs) {
                send({type: 'sqlite', op: 'delete', table: String(table), where: String(whereClause)});
                return this.delete(table, whereClause, whereArgs);
            };

            send({type: 'sqlite_hooks_installed'});
        });
        """
        return self.inject_script(script_src, "sqlite_intercept")

    def intercept_file_io(self) -> Dict[str, Any]:
        """Intercepta operacoes de I/O de arquivo."""
        script_src = """
        Java.perform(function() {
            var File = Java.use('java.io.File');
            var FileInputStream = Java.use('java.io.FileInputStream');
            var FileOutputStream = Java.use('java.io.FileOutputStream');

            FileInputStream.$init.overloads.forEach(function(overload) {
                overload.implementation = function() {
                    var path = '';
                    try {
                        if (arguments[0] instanceof Java.use('java.io.File')) {
                            path = arguments[0].getAbsolutePath();
                        } else {
                            path = String(arguments[0]);
                        }
                    } catch(e) { path = String(arguments[0]); }
                    send({type: 'file_io', op: 'read', path: path});
                    return overload.apply(this, arguments);
                };
            });

            FileOutputStream.$init.overloads.forEach(function(overload) {
                overload.implementation = function() {
                    var path = '';
                    try {
                        if (arguments[0] instanceof Java.use('java.io.File')) {
                            path = arguments[0].getAbsolutePath();
                        } else {
                            path = String(arguments[0]);
                        }
                    } catch(e) { path = String(arguments[0]); }
                    send({type: 'file_io', op: 'write', path: path});
                    return overload.apply(this, arguments);
                };
            });

            send({type: 'file_io_hooks_installed'});
        });
        """
        return self.inject_script(script_src, "file_io_intercept")

    # ─────────────────────────────────────────────────────────────────────
    # STATUS
    # ─────────────────────────────────────────────────────────────────────

    def get_status(self) -> Dict[str, Any]:
        """Retorna status completo do engine."""
        return {
            "frida_available": FRIDA_AVAILABLE,
            "frida_version": frida.__version__ if FRIDA_AVAILABLE else None,
            "device": str(self._device) if self._device else None,
            "session_active": self._session is not None,
            "loaded_scripts": list(self._scripts.keys()),
            "message_count": len(self._messages),
            "message_buffer_size": self.message_buffer_size,
            "server_path": self.server_path,
            "scripts_dir": str(self.scripts_dir),
            "scripts_available": (
                len(list(self.scripts_dir.glob("*.js")))
                if self.scripts_dir.exists()
                else 0
            ),
            "port": self.port,
            "enable_jit": self.enable_jit,
        }
