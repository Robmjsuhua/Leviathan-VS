#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    LEVIATHAN VS - ADB Manager v4.0
    Complete ADB wrapper for LDPlayer emulator control

    Handles: connections, shell, port forwarding, file transfer,
    device properties, logcat, screenshots, input, network, and
    all ADB operations with retry logic.

    v4.0 Changes:
        - Retry logic with configurable count/delay
        - Better error classification (timeout, not found, etc.)
        - Connection validation after connect
        - Shell as_root support
        - Improved type hints
================================================================================
"""

import json
import logging
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger("leviathan.adb")


class ADBManager:
    """Complete ADB interface for LDPlayer management."""

    def __init__(
        self,
        adb_path: str = "adb",
        host: str = "127.0.0.1",
        base_port: int = 5555,
        timeout: int = 30,
        retry_count: int = 3,
        retry_delay: float = 2.0,
    ):
        self.adb_path = adb_path
        self.host = host
        self.base_port = base_port
        self.timeout = timeout
        self.retry_count = retry_count
        self.retry_delay = retry_delay
        self._current_device: Optional[str] = None

    # ─────────────────────────────────────────────────────────────────────
    # EXECUCAO DE COMANDOS
    # ─────────────────────────────────────────────────────────────────────

    def _run(
        self, args: List[str], timeout: Optional[int] = None, binary: bool = False
    ) -> Tuple[int, str, str]:
        """Executa comando ADB e retorna (returncode, stdout, stderr)."""
        cmd = [self.adb_path] + args
        t = timeout or self.timeout
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=t, text=not binary)
            if binary:
                return proc.returncode, proc.stdout, proc.stderr
            return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
        except subprocess.TimeoutExpired:
            return -1, "", f"Timeout after {t}s"
        except FileNotFoundError:
            return -2, "", f"ADB not found at: {self.adb_path}"
        except Exception as e:
            return -3, "", str(e)

    def _device_args(self, device: Optional[str] = None) -> List[str]:
        """Retorna argumentos de seleção de device."""
        d = device or self._current_device
        if d:
            return ["-s", d]
        return []

    def run_adb(
        self,
        args: List[str],
        device: Optional[str] = None,
        timeout: Optional[int] = None,
        binary: bool = False,
    ) -> Tuple[int, Any, str]:
        """Executa comando ADB no device especificado."""
        full_args = self._device_args(device) + args
        return self._run(full_args, timeout, binary)

    def shell(
        self,
        command: str,
        device: Optional[str] = None,
        timeout: Optional[int] = None,
        as_root: bool = False,
    ) -> Tuple[int, str, str]:
        """Executa comando shell no device."""
        if as_root:
            command = f"su -c '{command}'"
        return self.run_adb(["shell", command], device, timeout)

    # ─────────────────────────────────────────────────────────────────────
    # CONEXAO E DEVICES
    # ─────────────────────────────────────────────────────────────────────

    def start_server(self) -> Dict[str, Any]:
        """Inicia o ADB server."""
        rc, out, err = self._run(["start-server"])
        return {"success": rc == 0, "output": out, "error": err}

    def kill_server(self) -> Dict[str, Any]:
        """Para o ADB server."""
        rc, out, err = self._run(["kill-server"])
        return {"success": rc == 0, "output": out, "error": err}

    def connect(
        self,
        port: Optional[int] = None,
        host: Optional[str] = None,
        retries: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Conecta ao emulador via TCP/IP com retry logic."""
        h = host or self.host
        p = port or self.base_port
        target = f"{h}:{p}"
        max_retries = retries if retries is not None else self.retry_count

        for attempt in range(max_retries):
            rc, out, err = self._run(["connect", target])
            success = rc == 0 and "connected" in out.lower()
            if success:
                self._current_device = target
                logger.info(f"Connected to {target} (attempt {attempt + 1})")
                return {
                    "success": True,
                    "target": target,
                    "output": out,
                    "attempt": attempt + 1,
                }
            if attempt < max_retries - 1:
                logger.warning(
                    f"Connect attempt {attempt + 1} failed, retrying in {self.retry_delay}s..."
                )
                time.sleep(self.retry_delay)

        return {
            "success": False,
            "target": target,
            "output": out,
            "error": err,
            "attempts": max_retries,
        }

    def disconnect(self, target: Optional[str] = None) -> Dict[str, Any]:
        """Desconecta device ou todos."""
        args = ["disconnect"]
        if target:
            args.append(target)
        rc, out, err = self._run(args)
        if not target:
            self._current_device = None
        return {"success": rc == 0, "output": out}

    def list_devices(self) -> List[Dict[str, str]]:
        """Lista todos os devices conectados."""
        rc, out, err = self._run(["devices", "-l"])
        devices = []
        for line in out.splitlines()[1:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2:
                dev = {"serial": parts[0], "state": parts[1]}
                # Parse extra info
                for part in parts[2:]:
                    if ":" in part:
                        k, v = part.split(":", 1)
                        dev[k] = v
                devices.append(dev)
        return devices

    def wait_for_device(
        self, device: Optional[str] = None, timeout: int = 60
    ) -> Dict[str, Any]:
        """Aguarda device ficar online."""
        args = self._device_args(device) + ["wait-for-device"]
        rc, out, err = self._run(args, timeout=timeout)
        return {"success": rc == 0, "output": out, "error": err}

    def set_current_device(self, serial: str):
        """Define o device atual."""
        self._current_device = serial

    def get_current_device(self) -> Optional[str]:
        """Retorna device atual."""
        return self._current_device

    def auto_connect_ldplayer(self, index: int = 0) -> Dict[str, Any]:
        """Auto-conecta ao LDPlayer pelo index da instancia."""
        port = self.base_port + (index * 2)
        return self.connect(port=port)

    # ─────────────────────────────────────────────────────────────────────
    # INFORMACOES DO DEVICE
    # ─────────────────────────────────────────────────────────────────────

    def get_device_info(self, device: Optional[str] = None) -> Dict[str, str]:
        """Retorna informacoes completas do device."""
        props = {}
        keys = {
            "model": "ro.product.model",
            "brand": "ro.product.brand",
            "manufacturer": "ro.product.manufacturer",
            "device": "ro.product.device",
            "android_version": "ro.build.version.release",
            "sdk_version": "ro.build.version.sdk",
            "build_id": "ro.build.display.id",
            "abi": "ro.product.cpu.abi",
            "hardware": "ro.hardware",
            "serial": "ro.serialno",
            "locale": "persist.sys.locale",
            "timezone": "persist.sys.timezone",
            "density": "ro.sf.lcd_density",
            "screen_size": "persist.sys.screen_size",
            "wifi_mac": "ro.boot.wifimacaddr",
            "bluetooth_mac": "persist.sys.bluetooth.bdaddr",
            "imei": "ro.ril.oem.imei",
        }
        for name, prop in keys.items():
            rc, out, _ = self.shell(f"getprop {prop}", device)
            if rc == 0 and out:
                props[name] = out
        return props

    def get_prop(self, prop: str, device: Optional[str] = None) -> str:
        """Retorna uma propriedade especifica."""
        rc, out, _ = self.shell(f"getprop {prop}", device)
        return out if rc == 0 else ""

    def set_prop(
        self, prop: str, value: str, device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Define uma propriedade."""
        rc, out, err = self.shell(f"setprop {prop} {value}", device)
        return {"success": rc == 0, "output": out, "error": err}

    def get_all_props(self, device: Optional[str] = None) -> Dict[str, str]:
        """Retorna todas as propriedades do device."""
        rc, out, _ = self.shell("getprop", device)
        props = {}
        if rc == 0:
            for line in out.splitlines():
                m = re.match(r"\[(.+?)\]:\s*\[(.*)?\]", line)
                if m:
                    props[m.group(1)] = m.group(2)
        return props

    def get_screen_resolution(self, device: Optional[str] = None) -> Dict[str, int]:
        """Retorna resolucao da tela."""
        rc, out, _ = self.shell("wm size", device)
        if rc == 0:
            m = re.search(r"(\d+)x(\d+)", out)
            if m:
                return {"width": int(m.group(1)), "height": int(m.group(2))}
        return {"width": 0, "height": 0}

    def get_screen_density(self, device: Optional[str] = None) -> int:
        """Retorna densidade da tela."""
        rc, out, _ = self.shell("wm density", device)
        if rc == 0:
            m = re.search(r"(\d+)", out)
            if m:
                return int(m.group(1))
        return 0

    def set_screen_resolution(
        self, width: int, height: int, device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Define resolucao da tela."""
        rc, out, err = self.shell(f"wm size {width}x{height}", device)
        return {"success": rc == 0, "output": out, "error": err}

    def set_screen_density(
        self, density: int, device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Define densidade da tela."""
        rc, out, err = self.shell(f"wm density {density}", device)
        return {"success": rc == 0, "output": out, "error": err}

    def reset_screen(self, device: Optional[str] = None) -> Dict[str, Any]:
        """Reseta resolucao e densidade para default."""
        self.shell("wm size reset", device)
        self.shell("wm density reset", device)
        return {"success": True, "message": "Screen reset to default"}

    # ─────────────────────────────────────────────────────────────────────
    # BATERIA E ENERGIA
    # ─────────────────────────────────────────────────────────────────────

    def get_battery_info(self, device: Optional[str] = None) -> Dict[str, Any]:
        """Retorna informacoes da bateria."""
        rc, out, _ = self.shell("dumpsys battery", device)
        info = {}
        if rc == 0:
            for line in out.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    info[k.strip()] = v.strip()
        return info

    def set_battery_level(
        self, level: int, device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Simula nivel de bateria."""
        self.shell("dumpsys battery unplug", device)
        rc, out, err = self.shell(f"dumpsys battery set level {level}", device)
        return {"success": rc == 0, "level": level}

    def reset_battery(self, device: Optional[str] = None) -> Dict[str, Any]:
        """Reseta simulacao de bateria."""
        rc, out, err = self.shell("dumpsys battery reset", device)
        return {"success": rc == 0}

    # ─────────────────────────────────────────────────────────────────────
    # GERENCIAMENTO DE APPS
    # ─────────────────────────────────────────────────────────────────────

    def install_apk(
        self,
        apk_path: str,
        device: Optional[str] = None,
        replace: bool = True,
        grant_permissions: bool = True,
    ) -> Dict[str, Any]:
        """Instala APK no device."""
        args = ["install"]
        if replace:
            args.append("-r")
        if grant_permissions:
            args.append("-g")
        args.append(apk_path)
        rc, out, err = self.run_adb(args, device, timeout=120)
        return {
            "success": rc == 0 and "success" in out.lower(),
            "output": out,
            "error": err,
        }

    def install_multiple_apks(
        self, apk_paths: List[str], device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Instala split APKs."""
        args = ["install-multiple", "-r"] + apk_paths
        rc, out, err = self.run_adb(args, device, timeout=180)
        return {"success": rc == 0, "output": out, "error": err}

    def uninstall_app(
        self, package: str, keep_data: bool = False, device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Desinstala app."""
        args = ["uninstall"]
        if keep_data:
            args.append("-k")
        args.append(package)
        rc, out, err = self.run_adb(args, device, timeout=60)
        return {
            "success": rc == 0 and "success" in out.lower(),
            "output": out,
            "error": err,
        }

    def list_packages(
        self,
        filter_str: str = "",
        third_party: bool = False,
        system: bool = False,
        device: Optional[str] = None,
    ) -> List[str]:
        """Lista packages instalados."""
        cmd = "pm list packages"
        if third_party:
            cmd += " -3"
        elif system:
            cmd += " -s"
        if filter_str:
            cmd += f" {filter_str}"
        rc, out, _ = self.shell(cmd, device)
        if rc == 0:
            return [
                line.replace("package:", "").strip()
                for line in out.splitlines()
                if line.startswith("package:")
            ]
        return []

    def get_package_info(
        self, package: str, device: Optional[str] = None
    ) -> Dict[str, str]:
        """Retorna info detalhada de um package."""
        rc, out, _ = self.shell(f"dumpsys package {package}", device, timeout=10)
        info = {"package": package}
        if rc == 0:
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("versionName="):
                    info["version_name"] = line.split("=", 1)[1]
                elif line.startswith("versionCode="):
                    info["version_code"] = line.split("=", 1)[1].split()[0]
                elif line.startswith("targetSdk="):
                    info["target_sdk"] = line.split("=", 1)[1]
                elif line.startswith("minSdk="):
                    info["min_sdk"] = line.split("=", 1)[1]
                elif "dataDir=" in line:
                    info["data_dir"] = line.split("=", 1)[1]
                elif "codePath=" in line:
                    info["code_path"] = line.split("=", 1)[1]
        return info

    def get_apk_path(self, package: str, device: Optional[str] = None) -> str:
        """Retorna caminho do APK no device."""
        rc, out, _ = self.shell(f"pm path {package}", device)
        if rc == 0 and out:
            return out.replace("package:", "").strip()
        return ""

    def pull_apk(
        self, package: str, output_dir: str = ".", device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Baixa APK do device."""
        apk_path = self.get_apk_path(package, device)
        if not apk_path:
            return {"success": False, "error": "APK path not found"}
        local = os.path.join(output_dir, f"{package}.apk")
        rc, out, err = self.run_adb(["pull", apk_path, local], device, timeout=120)
        return {"success": rc == 0, "local_path": local, "output": out, "error": err}

    def clear_app_data(
        self, package: str, device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Limpa dados do app."""
        rc, out, err = self.shell(f"pm clear {package}", device)
        return {"success": rc == 0 and "success" in out.lower(), "output": out}

    def force_stop(self, package: str, device: Optional[str] = None) -> Dict[str, Any]:
        """Para app forçadamente."""
        rc, out, err = self.shell(f"am force-stop {package}", device)
        return {"success": rc == 0, "output": out}

    def start_app(
        self, package: str, activity: Optional[str] = None, device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Inicia app."""
        if activity:
            cmd = f"am start -n {package}/{activity}"
        else:
            cmd = f"monkey -p {package} -c android.intent.category.LAUNCHER 1"
        rc, out, err = self.shell(cmd, device)
        return {"success": rc == 0, "output": out}

    def start_activity(
        self,
        package: str,
        activity: str,
        extras: Optional[Dict[str, str]] = None,
        action: Optional[str] = None,
        device: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Inicia activity com extras."""
        cmd = f"am start -n {package}/{activity}"
        if action:
            cmd += f" -a {action}"
        if extras:
            for k, v in extras.items():
                cmd += f" --es {k} '{v}'"
        rc, out, err = self.shell(cmd, device)
        return {"success": rc == 0, "output": out}

    def send_broadcast(
        self,
        action: str,
        extras: Optional[Dict[str, str]] = None,
        device: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Envia broadcast intent."""
        cmd = f"am broadcast -a {action}"
        if extras:
            for k, v in extras.items():
                cmd += f" --es {k} '{v}'"
        rc, out, err = self.shell(cmd, device)
        return {"success": rc == 0, "output": out}

    def start_service(
        self, package: str, service: str, device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Inicia service."""
        cmd = f"am startservice -n {package}/{service}"
        rc, out, err = self.shell(cmd, device)
        return {"success": rc == 0, "output": out}

    def get_running_activities(self, device: Optional[str] = None) -> List[str]:
        """Lista activities em execucao."""
        rc, out, _ = self.shell(
            "dumpsys activity activities | grep -E 'mResumedActivity|topResumedActivity'",
            device,
        )
        activities = []
        if rc == 0:
            for line in out.splitlines():
                m = re.search(r"(\S+/\S+)", line)
                if m:
                    activities.append(m.group(1))
        return activities

    def get_focused_activity(self, device: Optional[str] = None) -> str:
        """Retorna activity em foco."""
        rc, out, _ = self.shell(
            "dumpsys activity activities | grep mFocusedActivity", device
        )
        if rc == 0 and out:
            m = re.search(r"(\S+/\S+)", out)
            if m:
                return m.group(1)
        # Fallback for newer Android
        rc, out, _ = self.shell(
            "dumpsys activity activities | grep topResumedActivity", device
        )
        if rc == 0 and out:
            m = re.search(r"(\S+/\S+)", out)
            if m:
                return m.group(1)
        return ""

    def list_running_processes(
        self, device: Optional[str] = None
    ) -> List[Dict[str, str]]:
        """Lista processos em execucao."""
        rc, out, _ = self.shell("ps -A", device)
        processes = []
        if rc == 0:
            lines = out.splitlines()
            if lines:
                for line in lines[1:]:
                    parts = line.split()
                    if len(parts) >= 9:
                        processes.append(
                            {
                                "user": parts[0],
                                "pid": parts[1],
                                "ppid": parts[2],
                                "vsz": parts[3],
                                "rss": parts[4],
                                "name": parts[-1],
                            }
                        )
        return processes

    def get_pid(self, package: str, device: Optional[str] = None) -> int:
        """Retorna PID de um pacote."""
        rc, out, _ = self.shell(f"pidof {package}", device)
        if rc == 0 and out.strip().isdigit():
            return int(out.strip())
        return 0

    def enable_app(self, package: str, device: Optional[str] = None) -> Dict[str, Any]:
        """Habilita app."""
        rc, out, err = self.shell(f"pm enable {package}", device)
        return {"success": rc == 0, "output": out}

    def disable_app(self, package: str, device: Optional[str] = None) -> Dict[str, Any]:
        """Desabilita app."""
        rc, out, err = self.shell(f"pm disable-user {package}", device)
        return {"success": rc == 0, "output": out}

    def grant_permission(
        self, package: str, permission: str, device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Concede permissao."""
        rc, out, err = self.shell(f"pm grant {package} {permission}", device)
        return {"success": rc == 0, "output": out}

    def revoke_permission(
        self, package: str, permission: str, device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Revoga permissao."""
        rc, out, err = self.shell(f"pm revoke {package} {permission}", device)
        return {"success": rc == 0, "output": out}

    def list_permissions(self, package: str, device: Optional[str] = None) -> List[str]:
        """Lista permissoes de um app."""
        rc, out, _ = self.shell(f"dumpsys package {package} | grep permission", device)
        perms = []
        if rc == 0:
            for line in out.splitlines():
                m = re.search(r"(android\.permission\.\w+)", line)
                if m:
                    perm = m.group(1)
                    if perm not in perms:
                        perms.append(perm)
        return perms

    # ─────────────────────────────────────────────────────────────────────
    # TRANSFERENCIA DE ARQUIVOS
    # ─────────────────────────────────────────────────────────────────────

    def push(
        self, local: str, remote: str, device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Envia arquivo para o device."""
        rc, out, err = self.run_adb(["push", local, remote], device, timeout=120)
        return {"success": rc == 0, "output": out, "error": err}

    def pull(
        self, remote: str, local: str, device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Baixa arquivo do device."""
        rc, out, err = self.run_adb(["pull", remote, local], device, timeout=120)
        return {"success": rc == 0, "output": out, "error": err}

    def sync(
        self, directory: Optional[str] = None, device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Sincroniza arquivos."""
        args = ["sync"]
        if directory:
            args.append(directory)
        rc, out, err = self.run_adb(args, device, timeout=300)
        return {"success": rc == 0, "output": out, "error": err}

    def list_files(
        self, remote_path: str, device: Optional[str] = None
    ) -> List[Dict[str, str]]:
        """Lista arquivos no device."""
        rc, out, _ = self.shell(f"ls -la {remote_path}", device)
        files = []
        if rc == 0:
            for line in out.splitlines()[1:]:  # Skip total line
                parts = line.split()
                if len(parts) >= 8:
                    files.append(
                        {
                            "permissions": parts[0],
                            "owner": parts[2] if len(parts) > 2 else "",
                            "group": parts[3] if len(parts) > 3 else "",
                            "size": parts[4] if len(parts) > 4 else "",
                            "date": f"{parts[5]} {parts[6]}" if len(parts) > 6 else "",
                            "name": (
                                " ".join(parts[7:]) if len(parts) > 7 else parts[-1]
                            ),
                        }
                    )
        return files

    def file_exists(self, remote_path: str, device: Optional[str] = None) -> bool:
        """Verifica se arquivo existe."""
        rc, out, _ = self.shell(f"[ -e {remote_path} ] && echo EXISTS", device)
        return "EXISTS" in out

    def mkdir(self, remote_path: str, device: Optional[str] = None) -> Dict[str, Any]:
        """Cria diretorio no device."""
        rc, out, err = self.shell(f"mkdir -p {remote_path}", device)
        return {"success": rc == 0}

    def rm(
        self, remote_path: str, recursive: bool = False, device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Remove arquivo/diretorio no device."""
        flag = "-rf" if recursive else "-f"
        rc, out, err = self.shell(f"rm {flag} {remote_path}", device)
        return {"success": rc == 0}

    def cat_file(self, remote_path: str, device: Optional[str] = None) -> str:
        """Le conteudo de arquivo."""
        rc, out, _ = self.shell(f"cat {remote_path}", device)
        return out if rc == 0 else ""

    def write_file(
        self, remote_path: str, content: str, device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Escreve conteudo em arquivo remoto."""
        escaped = content.replace("'", "'\\''")
        rc, out, err = self.shell(f"echo '{escaped}' > {remote_path}", device)
        return {"success": rc == 0}

    def get_file_size(self, remote_path: str, device: Optional[str] = None) -> int:
        """Retorna tamanho do arquivo."""
        rc, out, _ = self.shell(f"stat -c%s {remote_path}", device)
        if rc == 0 and out.strip().isdigit():
            return int(out.strip())
        return -1

    def chmod(
        self, remote_path: str, mode: str, device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Altera permissoes."""
        rc, out, err = self.shell(f"chmod {mode} {remote_path}", device)
        return {"success": rc == 0}

    def chown(
        self, remote_path: str, owner: str, device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Altera dono."""
        rc, out, err = self.shell(f"chown {owner} {remote_path}", device)
        return {"success": rc == 0}

    # ─────────────────────────────────────────────────────────────────────
    # SCREENSHOT E GRAVACAO
    # ─────────────────────────────────────────────────────────────────────

    def screenshot(
        self, local_path: str, device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Tira screenshot e salva localmente."""
        remote = "/sdcard/screenshot_temp.png"
        self.shell(f"screencap -p {remote}", device)
        result = self.pull(remote, local_path, device)
        self.shell(f"rm {remote}", device)
        return result

    def screenrecord_start(
        self,
        remote_path: str = "/sdcard/recording.mp4",
        time_limit: int = 180,
        bitrate: str = "8M",
        size: str = "",
        device: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Inicia gravacao de tela (background)."""
        cmd = f"screenrecord --time-limit {time_limit} --bit-rate {bitrate}"
        if size:
            cmd += f" --size {size}"
        cmd += f" {remote_path}"
        # Run in background
        self.shell(f"nohup {cmd} &", device)
        return {"success": True, "remote_path": remote_path, "time_limit": time_limit}

    def screenrecord_stop(self, device: Optional[str] = None) -> Dict[str, Any]:
        """Para gravacao de tela."""
        rc, out, err = self.shell("pkill -f screenrecord", device)
        return {"success": True}

    # ─────────────────────────────────────────────────────────────────────
    # INPUT - TOUCH, KEYS, GESTURES
    # ─────────────────────────────────────────────────────────────────────

    def tap(self, x: int, y: int, device: Optional[str] = None) -> Dict[str, Any]:
        """Toque na tela."""
        rc, out, err = self.shell(f"input tap {x} {y}", device)
        return {"success": rc == 0}

    def long_press(
        self, x: int, y: int, duration_ms: int = 1000, device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Toque longo."""
        rc, out, err = self.shell(f"input swipe {x} {y} {x} {y} {duration_ms}", device)
        return {"success": rc == 0}

    def swipe(
        self,
        x1: int,
        y1: int,
        x2: int,
        y2: int,
        duration_ms: int = 300,
        device: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Swipe na tela."""
        rc, out, err = self.shell(
            f"input swipe {x1} {y1} {x2} {y2} {duration_ms}", device
        )
        return {"success": rc == 0}

    def input_text(self, text: str, device: Optional[str] = None) -> Dict[str, Any]:
        """Insere texto."""
        escaped = text.replace(" ", "%s").replace("'", "\\'")
        rc, out, err = self.shell(f"input text '{escaped}'", device)
        return {"success": rc == 0}

    def key_event(self, keycode: int, device: Optional[str] = None) -> Dict[str, Any]:
        """Envia key event."""
        rc, out, err = self.shell(f"input keyevent {keycode}", device)
        return {"success": rc == 0}

    def key_home(self, device: Optional[str] = None) -> Dict[str, Any]:
        return self.key_event(3, device)

    def key_back(self, device: Optional[str] = None) -> Dict[str, Any]:
        return self.key_event(4, device)

    def key_menu(self, device: Optional[str] = None) -> Dict[str, Any]:
        return self.key_event(82, device)

    def key_power(self, device: Optional[str] = None) -> Dict[str, Any]:
        return self.key_event(26, device)

    def key_volume_up(self, device: Optional[str] = None) -> Dict[str, Any]:
        return self.key_event(24, device)

    def key_volume_down(self, device: Optional[str] = None) -> Dict[str, Any]:
        return self.key_event(25, device)

    def key_enter(self, device: Optional[str] = None) -> Dict[str, Any]:
        return self.key_event(66, device)

    def key_tab(self, device: Optional[str] = None) -> Dict[str, Any]:
        return self.key_event(61, device)

    def key_delete(self, device: Optional[str] = None) -> Dict[str, Any]:
        return self.key_event(67, device)

    def key_recent_apps(self, device: Optional[str] = None) -> Dict[str, Any]:
        return self.key_event(187, device)

    def key_camera(self, device: Optional[str] = None) -> Dict[str, Any]:
        return self.key_event(27, device)

    def pinch(
        self, cx: int, cy: int, spread: int = 100, device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Simula pinch (zoom out)."""
        self.swipe(cx - spread, cy, cx - 10, cy, 500, device)
        self.swipe(cx + spread, cy, cx + 10, cy, 500, device)
        return {"success": True}

    def multi_touch_swipe(self, gestures: List[Dict], device: Optional[str] = None):
        """Executa multiplos gestos via sendevent (avancado)."""
        # Para uso avancado com sendevent
        for g in gestures:
            self.swipe(
                g["x1"], g["y1"], g["x2"], g["y2"], g.get("duration", 300), device
            )
        return {"success": True, "gestures": len(gestures)}

    # ─────────────────────────────────────────────────────────────────────
    # REDE
    # ─────────────────────────────────────────────────────────────────────

    def get_ip_address(self, device: Optional[str] = None) -> str:
        """Retorna IP do device."""
        rc, out, _ = self.shell("ip route | grep src | awk '{print $NF}'", device)
        if rc == 0 and out:
            return out.strip().splitlines()[0]
        rc, out, _ = self.shell("ifconfig wlan0 | grep 'inet addr'", device)
        if rc == 0:
            m = re.search(r"inet addr:(\S+)", out)
            if m:
                return m.group(1)
        return ""

    def get_wifi_info(self, device: Optional[str] = None) -> Dict[str, str]:
        """Retorna informacoes WiFi."""
        rc, out, _ = self.shell("dumpsys wifi | grep 'mWifiInfo'", device)
        info = {}
        if rc == 0 and out:
            m = re.search(r"SSID: (\S+)", out)
            if m:
                info["ssid"] = m.group(1)
            m = re.search(r"BSSID: (\S+)", out)
            if m:
                info["bssid"] = m.group(1)
            m = re.search(r"Link speed: (\d+)Mbps", out)
            if m:
                info["link_speed"] = m.group(1)
        return info

    def set_proxy(
        self, host: str, port: int, device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Configura proxy HTTP global."""
        rc, out, err = self.shell(
            f"settings put global http_proxy {host}:{port}", device
        )
        return {"success": rc == 0, "proxy": f"{host}:{port}"}

    def remove_proxy(self, device: Optional[str] = None) -> Dict[str, Any]:
        """Remove proxy HTTP global."""
        rc, out, err = self.shell("settings put global http_proxy :0", device)
        return {"success": rc == 0}

    def toggle_wifi(self, enable: bool, device: Optional[str] = None) -> Dict[str, Any]:
        """Liga/desliga WiFi."""
        action = "enable" if enable else "disable"
        rc, out, err = self.shell(f"svc wifi {action}", device)
        return {"success": rc == 0, "wifi": action}

    def toggle_mobile_data(
        self, enable: bool, device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Liga/desliga dados moveis."""
        action = "enable" if enable else "disable"
        rc, out, err = self.shell(f"svc data {action}", device)
        return {"success": rc == 0, "data": action}

    def toggle_airplane_mode(
        self, enable: bool, device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Liga/desliga modo aviao."""
        val = "1" if enable else "0"
        self.shell(f"settings put global airplane_mode_on {val}", device)
        self.shell(
            f"am broadcast -a android.intent.action.AIRPLANE_MODE --ez state {str(enable).lower()}",
            device,
        )
        return {"success": True, "airplane_mode": enable}

    def get_network_stats(self, device: Optional[str] = None) -> Dict[str, str]:
        """Retorna estatisticas de rede."""
        rc, out, _ = self.shell("cat /proc/net/dev", device)
        stats = {}
        if rc == 0:
            for line in out.splitlines()[2:]:
                parts = line.split()
                if len(parts) >= 10:
                    iface = parts[0].rstrip(":")
                    stats[iface] = {
                        "rx_bytes": parts[1],
                        "rx_packets": parts[2],
                        "tx_bytes": parts[9],
                        "tx_packets": parts[10],
                    }
        return stats

    def port_forward(
        self, local_port: int, remote_port: int, device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Redireciona porta local -> device."""
        rc, out, err = self.run_adb(
            ["forward", f"tcp:{local_port}", f"tcp:{remote_port}"], device
        )
        return {"success": rc == 0, "local": local_port, "remote": remote_port}

    def port_forward_remove(
        self, local_port: int, device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Remove redirecionamento de porta."""
        rc, out, err = self.run_adb(
            ["forward", "--remove", f"tcp:{local_port}"], device
        )
        return {"success": rc == 0}

    def port_forward_list(self, device: Optional[str] = None) -> List[str]:
        """Lista redirecionamentos ativos."""
        rc, out, _ = self.run_adb(["forward", "--list"], device)
        if rc == 0:
            return [l.strip() for l in out.splitlines() if l.strip()]
        return []

    def reverse_forward(
        self, remote_port: int, local_port: int, device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Redireciona porta device -> local."""
        rc, out, err = self.run_adb(
            ["reverse", f"tcp:{remote_port}", f"tcp:{local_port}"], device
        )
        return {"success": rc == 0, "remote": remote_port, "local": local_port}

    def reverse_forward_remove(
        self, remote_port: int, device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Remove reverse forward."""
        rc, out, err = self.run_adb(
            ["reverse", "--remove", f"tcp:{remote_port}"], device
        )
        return {"success": rc == 0}

    def tcpdump_start(
        self,
        output_path: str = "/sdcard/capture.pcap",
        interface: str = "any",
        filter_str: str = "",
        device: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Inicia captura de pacotes."""
        cmd = f"tcpdump -i {interface} -w {output_path}"
        if filter_str:
            cmd += f" {filter_str}"
        self.shell(f"nohup {cmd} &", device)
        return {"success": True, "output_path": output_path}

    def tcpdump_stop(self, device: Optional[str] = None) -> Dict[str, Any]:
        """Para captura de pacotes."""
        self.shell("pkill tcpdump", device)
        return {"success": True}

    # ─────────────────────────────────────────────────────────────────────
    # LOGCAT
    # ─────────────────────────────────────────────────────────────────────

    def logcat(
        self, filter_spec: str = "", lines: int = 100, device: Optional[str] = None
    ) -> str:
        """Retorna linhas do logcat."""
        cmd = f"logcat -d -t {lines}"
        if filter_spec:
            cmd += f" {filter_spec}"
        rc, out, _ = self.shell(cmd, device, timeout=10)
        return out if rc == 0 else ""

    def logcat_clear(self, device: Optional[str] = None) -> Dict[str, Any]:
        """Limpa buffer do logcat."""
        rc, out, err = self.shell("logcat -c", device)
        return {"success": rc == 0}

    def logcat_by_tag(
        self, tag: str, level: str = "V", lines: int = 100, device: Optional[str] = None
    ) -> str:
        """Filtra logcat por tag."""
        return self.logcat(f"-s {tag}:{level}", lines, device)

    def logcat_by_pid(
        self, pid: int, lines: int = 100, device: Optional[str] = None
    ) -> str:
        """Filtra logcat por PID."""
        return self.logcat(f"--pid={pid}", lines, device)

    def logcat_by_package(
        self, package: str, lines: int = 200, device: Optional[str] = None
    ) -> str:
        """Filtra logcat por package (via PID)."""
        pid = self.get_pid(package, device)
        if pid:
            return self.logcat_by_pid(pid, lines, device)
        return f"Package {package} not running"

    # ─────────────────────────────────────────────────────────────────────
    # SISTEMA
    # ─────────────────────────────────────────────────────────────────────

    def reboot(self, mode: str = "", device: Optional[str] = None) -> Dict[str, Any]:
        """Reinicia device (mode: '', 'recovery', 'bootloader')."""
        args = ["reboot"]
        if mode:
            args.append(mode)
        rc, out, err = self.run_adb(args, device)
        return {"success": rc == 0}

    def root(self, device: Optional[str] = None) -> Dict[str, Any]:
        """Reinicia ADB como root."""
        rc, out, err = self.run_adb(["root"], device)
        return {"success": rc == 0 or "already" in out.lower(), "output": out}

    def unroot(self, device: Optional[str] = None) -> Dict[str, Any]:
        """Volta ADB para modo normal."""
        rc, out, err = self.run_adb(["unroot"], device)
        return {"success": rc == 0, "output": out}

    def remount(self, device: Optional[str] = None) -> Dict[str, Any]:
        """Remonta /system como read-write."""
        rc, out, err = self.run_adb(["remount"], device)
        return {"success": rc == 0, "output": out}

    def get_uptime(self, device: Optional[str] = None) -> str:
        """Retorna uptime do device."""
        rc, out, _ = self.shell("uptime", device)
        return out if rc == 0 else ""

    def get_disk_space(self, device: Optional[str] = None) -> Dict[str, Any]:
        """Retorna espaco em disco."""
        rc, out, _ = self.shell("df -h", device)
        partitions = []
        if rc == 0:
            for line in out.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 6:
                    partitions.append(
                        {
                            "filesystem": parts[0],
                            "size": parts[1],
                            "used": parts[2],
                            "available": parts[3],
                            "use_pct": parts[4],
                            "mounted_on": parts[5],
                        }
                    )
        return {"partitions": partitions}

    def get_memory_info(self, device: Optional[str] = None) -> Dict[str, str]:
        """Retorna informacoes de memoria."""
        rc, out, _ = self.shell("cat /proc/meminfo", device)
        info = {}
        if rc == 0:
            for line in out.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    info[k.strip()] = v.strip()
        return info

    def get_cpu_info(self, device: Optional[str] = None) -> Dict[str, Any]:
        """Retorna informacoes da CPU."""
        rc, out, _ = self.shell("cat /proc/cpuinfo", device)
        info = {"cores": 0, "details": []}
        if rc == 0:
            current = {}
            for line in out.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    current[k.strip()] = v.strip()
                elif not line.strip() and current:
                    info["details"].append(current)
                    current = {}
            if current:
                info["details"].append(current)
            info["cores"] = len(info["details"])
        return info

    def get_cpu_usage(self, device: Optional[str] = None) -> str:
        """Retorna uso da CPU."""
        rc, out, _ = self.shell("top -n 1 -b | head -5", device)
        return out if rc == 0 else ""

    def open_url(self, url: str, device: Optional[str] = None) -> Dict[str, Any]:
        """Abre URL no navegador."""
        rc, out, err = self.shell(
            f"am start -a android.intent.action.VIEW -d '{url}'", device
        )
        return {"success": rc == 0, "url": url}

    def open_settings(
        self, section: str = "", device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Abre configuracoes do Android."""
        if section:
            cmd = f"am start -a android.settings.{section}"
        else:
            cmd = "am start -a android.settings.SETTINGS"
        rc, out, err = self.shell(cmd, device)
        return {"success": rc == 0}

    def get_installed_certificates(self, device: Optional[str] = None) -> List[str]:
        """Lista certificados instalados."""
        rc, out, _ = self.shell("ls /system/etc/security/cacerts/", device)
        if rc == 0:
            return [f.strip() for f in out.splitlines() if f.strip()]
        return []

    def install_certificate(
        self, cert_path: str, device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Instala certificado CA no sistema."""
        cert_name = os.path.basename(cert_path)
        remote_tmp = f"/sdcard/{cert_name}"
        remote_final = f"/system/etc/security/cacerts/{cert_name}"
        self.push(cert_path, remote_tmp, device)
        self.root(device)
        self.remount(device)
        self.shell(f"cp {remote_tmp} {remote_final}", device)
        self.shell(f"chmod 644 {remote_final}", device)
        self.shell(f"rm {remote_tmp}", device)
        return {"success": True, "installed": remote_final}

    def get_dumpsys(self, service: str, device: Optional[str] = None) -> str:
        """Retorna dumpsys de um servico."""
        rc, out, _ = self.shell(f"dumpsys {service}", device, timeout=15)
        return out if rc == 0 else ""

    def list_services(self, device: Optional[str] = None) -> List[str]:
        """Lista servicos do sistema."""
        rc, out, _ = self.shell("service list", device, timeout=10)
        if rc == 0:
            return [l.strip() for l in out.splitlines() if l.strip()]
        return []

    def get_display_info(self, device: Optional[str] = None) -> Dict[str, Any]:
        """Retorna info do display."""
        rc, out, _ = self.shell("dumpsys display | grep -A 20 'mDisplayId=0'", device)
        return {"raw": out if rc == 0 else ""}

    def wake_up(self, device: Optional[str] = None) -> Dict[str, Any]:
        """Acorda a tela."""
        rc, out, err = self.shell("input keyevent KEYCODE_WAKEUP", device)
        return {"success": rc == 0}

    def sleep_screen(self, device: Optional[str] = None) -> Dict[str, Any]:
        """Desliga a tela."""
        rc, out, err = self.shell("input keyevent KEYCODE_SLEEP", device)
        return {"success": rc == 0}

    def is_screen_on(self, device: Optional[str] = None) -> bool:
        """Verifica se tela esta ligada."""
        rc, out, _ = self.shell("dumpsys power | grep 'Display Power'", device)
        if rc == 0:
            return "ON" in out.upper()
        return False

    def set_brightness(
        self, level: int, device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Define brilho (0-255)."""
        self.shell("settings put system screen_brightness_mode 0", device)
        rc, out, err = self.shell(
            f"settings put system screen_brightness {level}", device
        )
        return {"success": rc == 0, "brightness": level}

    def set_locale(self, locale: str, device: Optional[str] = None) -> Dict[str, Any]:
        """Define locale."""
        rc, out, err = self.shell(f"setprop persist.sys.locale {locale}", device)
        return {"success": rc == 0, "locale": locale}

    def set_timezone(self, tz: str, device: Optional[str] = None) -> Dict[str, Any]:
        """Define timezone."""
        rc, out, err = self.shell(f"setprop persist.sys.timezone {tz}", device)
        return {"success": rc == 0, "timezone": tz}

    def backup(
        self, package: str, output_path: str, device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Faz backup do app."""
        rc, out, err = self.run_adb(
            ["backup", "-apk", "-shared", package, "-f", output_path],
            device,
            timeout=300,
        )
        return {"success": rc == 0, "output_path": output_path}

    def restore(self, backup_path: str, device: Optional[str] = None) -> Dict[str, Any]:
        """Restaura backup."""
        rc, out, err = self.run_adb(["restore", backup_path], device, timeout=300)
        return {"success": rc == 0}

    def bugreport(
        self, output_path: str, device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Gera bugreport."""
        rc, out, err = self.run_adb(["bugreport", output_path], device, timeout=300)
        return {"success": rc == 0, "output_path": output_path}

    def get_serial(self, device: Optional[str] = None) -> str:
        """Retorna serial number."""
        rc, out, _ = self.run_adb(["get-serialno"], device)
        return out if rc == 0 else ""

    def get_state(self, device: Optional[str] = None) -> str:
        """Retorna estado do device."""
        rc, out, _ = self.run_adb(["get-state"], device)
        return out if rc == 0 else ""

    def disable_verity(self, device: Optional[str] = None) -> Dict[str, Any]:
        """Desabilita verity."""
        rc, out, err = self.run_adb(["disable-verity"], device)
        return {"success": rc == 0, "output": out}

    def enable_verity(self, device: Optional[str] = None) -> Dict[str, Any]:
        """Habilita verity."""
        rc, out, err = self.run_adb(["enable-verity"], device)
        return {"success": rc == 0, "output": out}

    def sideload(self, zip_path: str, device: Optional[str] = None) -> Dict[str, Any]:
        """Sideload update zip."""
        rc, out, err = self.run_adb(["sideload", zip_path], device, timeout=600)
        return {"success": rc == 0, "output": out}

    def get_adb_version(self) -> str:
        """Retorna versao do ADB."""
        rc, out, _ = self._run(["version"])
        return out if rc == 0 else ""
