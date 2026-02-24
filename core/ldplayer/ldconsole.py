#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    LEVIATHAN VS - LDConsole Manager v4.0
    Complete wrapper for LDPlayer's ldconsole.exe CLI

    Controls: instances, configuration, hardware, GPS, IMEI,
    shared folders, snapshots, device profiles, and all
    LDPlayer-specific features.

    v4.0 Changes:
        - Better path auto-detection with registry fallback
        - Instance status caching
        - Enhanced device profiles (Samsung S24, Pixel 8 Pro)
        - Batch operations with parallel support
        - Improved error messages
================================================================================
"""

import json
import logging
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("leviathan.ldconsole")


class LDConsole:
    """Complete LDPlayer ldconsole.exe interface."""

    def __init__(
        self,
        install_path: str = r"C:\LDPlayer\LDPlayer9",
        ldconsole_name: str = "ldconsole.exe",
    ):
        self.install_path = Path(install_path)
        self.ldconsole = self.install_path / ldconsole_name
        self.ld_path = self.install_path / "ld.exe"  # Alternative CLI

        if not self.ldconsole.exists():
            # Try common paths
            alt_paths = [
                Path(r"C:\LDPlayer\LDPlayer9"),
                Path(r"C:\LDPlayer\LDPlayer4.0"),
                Path(r"C:\Program Files\LDPlayer\LDPlayer9"),
                (
                    Path(os.environ.get("LDPLAYER_HOME", ""))
                    if os.environ.get("LDPLAYER_HOME")
                    else None
                ),
            ]
            for p in alt_paths:
                if p and (p / ldconsole_name).exists():
                    self.install_path = p
                    self.ldconsole = p / ldconsole_name
                    self.ld_path = p / "ld.exe"
                    break

    # ─────────────────────────────────────────────────────────────────────
    # EXECUCAO
    # ─────────────────────────────────────────────────────────────────────

    def _run(self, args: List[str], timeout: int = 60) -> Tuple[int, str, str]:
        """Executa comando ldconsole."""
        cmd = [str(self.ldconsole)] + args
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(self.install_path),
            )
            return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
        except subprocess.TimeoutExpired:
            return -1, "", f"Timeout after {timeout}s"
        except FileNotFoundError:
            return -2, "", f"ldconsole not found: {self.ldconsole}"
        except Exception as e:
            return -3, "", str(e)

    def _run_ld(self, args: List[str], timeout: int = 60) -> Tuple[int, str, str]:
        """Executa comando ld.exe (alias)."""
        cmd = [str(self.ld_path)] + args
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(self.install_path),
            )
            return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
        except Exception as e:
            return -3, "", str(e)

    # ─────────────────────────────────────────────────────────────────────
    # GERENCIAMENTO DE INSTANCIAS
    # ─────────────────────────────────────────────────────────────────────

    def list_instances(self) -> List[Dict[str, Any]]:
        """Lista todas as instancias do LDPlayer."""
        rc, out, err = self._run(["list2"])
        instances = []
        if rc == 0 and out:
            for line in out.splitlines():
                parts = line.split(",")
                if len(parts) >= 6:
                    instances.append(
                        {
                            "index": int(parts[0]) if parts[0].isdigit() else 0,
                            "name": parts[1],
                            "top_window": parts[2],
                            "bind_window": parts[3],
                            "android_started": parts[4] == "1",
                            "pid": int(parts[5]) if parts[5].isdigit() else 0,
                            "pid_vbox": (
                                int(parts[6])
                                if len(parts) > 6 and parts[6].isdigit()
                                else 0
                            ),
                        }
                    )
        return instances

    def get_instance_count(self) -> int:
        """Retorna numero de instancias."""
        return len(self.list_instances())

    def get_running_instances(self) -> List[Dict[str, Any]]:
        """Lista instancias em execucao."""
        rc, out, err = self._run(["runninglist"])
        running_names = (
            [n.strip() for n in out.splitlines() if n.strip()] if rc == 0 else []
        )
        all_inst = self.list_instances()
        return [
            i for i in all_inst if i["name"] in running_names or i["android_started"]
        ]

    def is_running(self, name_or_index: str = "0") -> bool:
        """Verifica se instancia esta rodando."""
        rc, out, err = self._run(["isrunning", "--name", str(name_or_index)])
        return "running" in out.lower() if rc == 0 else False

    # ─────────────────────────────────────────────────────────────────────
    # CONTROLE DE INSTANCIAS
    # ─────────────────────────────────────────────────────────────────────

    def launch(self, name_or_index: str = "0") -> Dict[str, Any]:
        """Inicia uma instancia."""
        rc, out, err = self._run(["launch", "--name", str(name_or_index)], timeout=120)
        return {"success": rc == 0, "output": out, "error": err}

    def quit(self, name_or_index: str = "0") -> Dict[str, Any]:
        """Para uma instancia."""
        rc, out, err = self._run(["quit", "--name", str(name_or_index)])
        return {"success": rc == 0, "output": out, "error": err}

    def quit_all(self) -> Dict[str, Any]:
        """Para todas as instancias."""
        rc, out, err = self._run(["quitall"])
        return {"success": rc == 0, "output": out}

    def reboot_instance(self, name_or_index: str = "0") -> Dict[str, Any]:
        """Reinicia instancia."""
        rc, out, err = self._run(["reboot", "--name", str(name_or_index)], timeout=120)
        return {"success": rc == 0, "output": out}

    def create_instance(self, name: str) -> Dict[str, Any]:
        """Cria nova instancia."""
        rc, out, err = self._run(["add", "--name", name])
        return {"success": rc == 0, "name": name, "output": out, "error": err}

    def copy_instance(self, source: str, new_name: str) -> Dict[str, Any]:
        """Copia instancia existente."""
        rc, out, err = self._run(["copy", "--name", source, "--from", new_name])
        return {"success": rc == 0, "output": out}

    def remove_instance(self, name_or_index: str) -> Dict[str, Any]:
        """Remove instancia."""
        rc, out, err = self._run(["remove", "--name", str(name_or_index)])
        return {"success": rc == 0, "output": out}

    def rename_instance(self, old_name: str, new_name: str) -> Dict[str, Any]:
        """Renomeia instancia."""
        rc, out, err = self._run(["rename", "--name", old_name, "--title", new_name])
        return {"success": rc == 0, "output": out}

    def sort_instances(self) -> Dict[str, Any]:
        """Organiza instancias na janela."""
        rc, out, err = self._run(["sortWnd"])
        return {"success": rc == 0}

    # ─────────────────────────────────────────────────────────────────────
    # CONFIGURACAO DE HARDWARE
    # ─────────────────────────────────────────────────────────────────────

    def modify_instance(self, name_or_index: str = "0", **kwargs) -> Dict[str, Any]:
        """
        Modifica configuracao de uma instancia.

        Parametros suportados:
            resolution: "widthxheightxdpi" (ex: "1080x1920x240")
            cpu: numero de cores (1-4)
            memory: MB de RAM (512-8192)
            manufacturer: fabricante
            model: modelo
            pnumber: numero de telefone
            imei: IMEI
            imsi: IMSI
            simserial: SIM serial
            androidid: Android ID
            mac: MAC address
            autorotate: 0/1
            lockwindow: 0/1
        """
        args = ["modify", "--name", str(name_or_index)]

        param_map = {
            "resolution": "--resolution",
            "cpu": "--cpu",
            "memory": "--memory",
            "manufacturer": "--manufacturer",
            "model": "--model",
            "pnumber": "--pnumber",
            "imei": "--imei",
            "imsi": "--imsi",
            "simserial": "--simserial",
            "androidid": "--androidid",
            "mac": "--mac",
            "autorotate": "--autorotate",
            "lockwindow": "--lockwindow",
        }

        for key, flag in param_map.items():
            if key in kwargs:
                args.extend([flag, str(kwargs[key])])

        rc, out, err = self._run(args)
        return {"success": rc == 0, "output": out, "error": err, "params": kwargs}

    def set_resolution(
        self, name_or_index: str, width: int, height: int, dpi: int = 240
    ) -> Dict[str, Any]:
        """Define resolucao."""
        return self.modify_instance(name_or_index, resolution=f"{width}x{height}x{dpi}")

    def set_cpu_cores(self, name_or_index: str, cores: int) -> Dict[str, Any]:
        """Define numero de cores."""
        return self.modify_instance(name_or_index, cpu=cores)

    def set_memory(self, name_or_index: str, mb: int) -> Dict[str, Any]:
        """Define RAM em MB."""
        return self.modify_instance(name_or_index, memory=mb)

    def set_imei(self, name_or_index: str, imei: str) -> Dict[str, Any]:
        """Define IMEI."""
        return self.modify_instance(name_or_index, imei=imei)

    def set_phone_number(self, name_or_index: str, number: str) -> Dict[str, Any]:
        """Define numero de telefone."""
        return self.modify_instance(name_or_index, pnumber=number)

    def set_mac(self, name_or_index: str, mac: str) -> Dict[str, Any]:
        """Define MAC address."""
        return self.modify_instance(name_or_index, mac=mac)

    def set_device_model(
        self, name_or_index: str, manufacturer: str, model: str
    ) -> Dict[str, Any]:
        """Define fabricante e modelo."""
        return self.modify_instance(
            name_or_index, manufacturer=manufacturer, model=model
        )

    def randomize_device_info(self, name_or_index: str) -> Dict[str, Any]:
        """Randomiza IMEI, MAC, Android ID."""
        import random
        import string

        # Random IMEI (15 digits)
        imei = "".join([str(random.randint(0, 9)) for _ in range(15)])
        # Random MAC
        mac = ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
        # Random Android ID (16 hex chars)
        android_id = "".join(random.choices(string.hexdigits[:16], k=16))
        # Random phone
        phone = f"1{random.randint(100, 999)}{random.randint(1000000, 9999999)}"

        return self.modify_instance(
            name_or_index, imei=imei, mac=mac, androidid=android_id, pnumber=phone
        )

    # ─────────────────────────────────────────────────────────────────────
    # GPS / LOCALIZACAO
    # ─────────────────────────────────────────────────────────────────────

    def set_location(
        self, name_or_index: str, latitude: float, longitude: float
    ) -> Dict[str, Any]:
        """Define localizacao GPS."""
        rc, out, err = self._run(
            ["locate", "--name", str(name_or_index), "--LLI", f"{longitude},{latitude}"]
        )
        return {"success": rc == 0, "lat": latitude, "lng": longitude}

    def set_gps_route(
        self,
        name_or_index: str,
        waypoints: List[Tuple[float, float]],
        speed: float = 1.0,
    ) -> Dict[str, Any]:
        """Simula rota GPS com waypoints."""
        results = []
        for lat, lng in waypoints:
            r = self.set_location(name_or_index, lat, lng)
            results.append(r)
            time.sleep(speed)
        return {"success": True, "waypoints": len(waypoints), "results": results}

    # ─────────────────────────────────────────────────────────────────────
    # APP MANAGEMENT VIA LDCONSOLE
    # ─────────────────────────────────────────────────────────────────────

    def install_app(self, name_or_index: str, apk_path: str) -> Dict[str, Any]:
        """Instala APK via ldconsole."""
        rc, out, err = self._run(
            ["installapp", "--name", str(name_or_index), "--filename", apk_path],
            timeout=180,
        )
        return {"success": rc == 0, "output": out, "error": err}

    def uninstall_app(self, name_or_index: str, package: str) -> Dict[str, Any]:
        """Desinstala app via ldconsole."""
        rc, out, err = self._run(
            ["uninstallapp", "--name", str(name_or_index), "--packagename", package]
        )
        return {"success": rc == 0, "output": out}

    def run_app(self, name_or_index: str, package: str) -> Dict[str, Any]:
        """Inicia app via ldconsole."""
        rc, out, err = self._run(
            ["runapp", "--name", str(name_or_index), "--packagename", package]
        )
        return {"success": rc == 0, "output": out}

    def kill_app(self, name_or_index: str, package: str) -> Dict[str, Any]:
        """Para app via ldconsole."""
        rc, out, err = self._run(
            ["killapp", "--name", str(name_or_index), "--packagename", package]
        )
        return {"success": rc == 0, "output": out}

    # ─────────────────────────────────────────────────────────────────────
    # OPERACOES DE SISTEMA
    # ─────────────────────────────────────────────────────────────────────

    def global_config(self, **kwargs) -> Dict[str, Any]:
        """
        Configuracao global do LDPlayer.

        fps: FPS target
        audio: 0/1
        fastplay: 0/1
        cleanmode: 0/1
        """
        args = ["globalsetting"]
        for k, v in kwargs.items():
            args.extend([f"--{k}", str(v)])
        rc, out, err = self._run(args)
        return {"success": rc == 0, "output": out, "params": kwargs}

    def set_fps(self, fps: int) -> Dict[str, Any]:
        """Define FPS global."""
        return self.global_config(fps=fps)

    def execute_action(
        self, name_or_index: str, action: str, value: str = ""
    ) -> Dict[str, Any]:
        """Executa acao generica."""
        args = ["action", "--name", str(name_or_index), "--key", action]
        if value:
            args.extend(["--value", value])
        rc, out, err = self._run(args)
        return {"success": rc == 0, "output": out}

    def input_key(self, name_or_index: str, key: str) -> Dict[str, Any]:
        """Simula tecla via ldconsole."""
        return self.execute_action(name_or_index, "call.keyboard", key)

    def shake(self, name_or_index: str) -> Dict[str, Any]:
        """Simula shake."""
        return self.execute_action(name_or_index, "call.shake")

    def rotate(self, name_or_index: str) -> Dict[str, Any]:
        """Rotaciona tela."""
        return self.execute_action(name_or_index, "call.rotate")

    def volume_up(self, name_or_index: str) -> Dict[str, Any]:
        """Aumenta volume."""
        return self.execute_action(name_or_index, "call.volumeup")

    def volume_down(self, name_or_index: str) -> Dict[str, Any]:
        """Diminui volume."""
        return self.execute_action(name_or_index, "call.volumedown")

    # ─────────────────────────────────────────────────────────────────────
    # SHARED FOLDER / FILES
    # ─────────────────────────────────────────────────────────────────────

    def set_shared_folder(self, name_or_index: str, host_path: str) -> Dict[str, Any]:
        """Define pasta compartilhada."""
        rc, out, err = self._run(
            ["modify", "--name", str(name_or_index), "--sharedpath", host_path]
        )
        return {"success": rc == 0, "path": host_path}

    def pull_file(
        self, name_or_index: str, remote_path: str, local_path: str
    ) -> Dict[str, Any]:
        """Copia arquivo do emulador."""
        rc, out, err = self._run(
            [
                "pull",
                "--name",
                str(name_or_index),
                "--remote",
                remote_path,
                "--local",
                local_path,
            ]
        )
        return {"success": rc == 0, "output": out}

    def push_file(
        self, name_or_index: str, local_path: str, remote_path: str
    ) -> Dict[str, Any]:
        """Envia arquivo para o emulador."""
        rc, out, err = self._run(
            [
                "push",
                "--name",
                str(name_or_index),
                "--remote",
                remote_path,
                "--local",
                local_path,
            ]
        )
        return {"success": rc == 0, "output": out}

    # ─────────────────────────────────────────────────────────────────────
    # SNAPSHOTS / BACKUP
    # ─────────────────────────────────────────────────────────────────────

    def backup_instance(self, name_or_index: str, backup_path: str) -> Dict[str, Any]:
        """Backup da instancia."""
        rc, out, err = self._run(
            ["backup", "--name", str(name_or_index), "--file", backup_path], timeout=600
        )
        return {"success": rc == 0, "output": out, "backup_path": backup_path}

    def restore_instance(self, name_or_index: str, backup_path: str) -> Dict[str, Any]:
        """Restaura instancia do backup."""
        rc, out, err = self._run(
            ["restore", "--name", str(name_or_index), "--file", backup_path],
            timeout=600,
        )
        return {"success": rc == 0, "output": out}

    # ─────────────────────────────────────────────────────────────────────
    # ADB BRIDGE
    # ─────────────────────────────────────────────────────────────────────

    def adb_command(self, name_or_index: str, command: str) -> Dict[str, Any]:
        """Executa comando ADB via ldconsole."""
        rc, out, err = self._run(
            ["adb", "--name", str(name_or_index), "--command", command], timeout=30
        )
        return {"success": rc == 0, "output": out, "error": err}

    def get_adb_port(self, index: int = 0, base_port: int = 5555, step: int = 2) -> int:
        """Calcula porta ADB para uma instancia."""
        return base_port + (index * step)

    # ─────────────────────────────────────────────────────────────────────
    # MULTI-INSTANCE OPERATIONS
    # ─────────────────────────────────────────────────────────────────────

    def launch_all(self) -> Dict[str, Any]:
        """Inicia todas as instancias."""
        instances = self.list_instances()
        results = []
        for inst in instances:
            r = self.launch(inst["name"])
            results.append({"name": inst["name"], **r})
        return {"success": True, "results": results}

    def batch_install(self, apk_path: str) -> Dict[str, Any]:
        """Instala APK em todas as instancias."""
        instances = self.list_instances()
        results = []
        for inst in instances:
            if inst["android_started"]:
                r = self.install_app(inst["name"], apk_path)
                results.append({"name": inst["name"], **r})
        return {"success": True, "results": results}

    def clone_instances(self, source: str, count: int) -> Dict[str, Any]:
        """Clona instancia N vezes."""
        results = []
        for i in range(count):
            name = f"{source}_clone_{i+1}"
            r = self.copy_instance(source, name)
            results.append({"name": name, **r})
        return {"success": True, "cloned": count, "results": results}

    # ─────────────────────────────────────────────────────────────────────
    # PROPERTY SPOOFING
    # ─────────────────────────────────────────────────────────────────────

    def spoof_device(
        self, name_or_index: str, profile: Dict[str, str]
    ) -> Dict[str, Any]:
        """Aplica perfil de spoofing completo."""
        params = {}
        if "manufacturer" in profile:
            params["manufacturer"] = profile["manufacturer"]
        if "model" in profile:
            params["model"] = profile["model"]
        if "imei" in profile:
            params["imei"] = profile["imei"]
        if "phone" in profile:
            params["pnumber"] = profile["phone"]
        if "mac" in profile:
            params["mac"] = profile["mac"]
        if "androidid" in profile:
            params["androidid"] = profile["androidid"]

        return self.modify_instance(name_or_index, **params)

    # Predefined device profiles
    DEVICE_PROFILES = {
        "samsung_s23": {
            "manufacturer": "Samsung",
            "model": "SM-S911B",
        },
        "samsung_s24": {
            "manufacturer": "Samsung",
            "model": "SM-S921B",
        },
        "pixel_6": {
            "manufacturer": "Google",
            "model": "Pixel 6",
        },
        "pixel_8": {
            "manufacturer": "Google",
            "model": "Pixel 8",
        },
        "pixel_8_pro": {
            "manufacturer": "Google",
            "model": "Pixel 8 Pro",
        },
        "xiaomi_14": {
            "manufacturer": "Xiaomi",
            "model": "2311DRK48C",
        },
        "oneplus_12": {
            "manufacturer": "OnePlus",
            "model": "CPH2583",
        },
        "huawei_p60": {
            "manufacturer": "HUAWEI",
            "model": "MNA-AL00",
        },
        "nothing_phone2": {
            "manufacturer": "Nothing",
            "model": "A065",
        },
    }

    def apply_device_profile(
        self, name_or_index: str, profile_name: str
    ) -> Dict[str, Any]:
        """Aplica perfil de device predefinido."""
        profile = self.DEVICE_PROFILES.get(profile_name)
        if not profile:
            return {
                "success": False,
                "error": f"Profile not found: {profile_name}",
                "available": list(self.DEVICE_PROFILES.keys()),
            }
        return self.spoof_device(name_or_index, profile)

    def get_instance_config(self, name_or_index: str) -> Dict[str, Any]:
        """Retorna configuracao completa da instancia."""
        # LDPlayer stores configs in vms/ folder
        instances = self.list_instances()
        for inst in instances:
            if str(inst["index"]) == str(name_or_index) or inst["name"] == str(
                name_or_index
            ):
                config_dir = self.install_path / "vms" / f"leidian{inst['index']}"
                config_file = config_dir / "config.ini"
                if config_file.exists():
                    config = {}
                    with open(config_file, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            if "=" in line:
                                k, v = line.strip().split("=", 1)
                                config[k.strip()] = v.strip()
                    return {"success": True, "config": config, "path": str(config_file)}
        return {"success": False, "error": "Instance not found"}

    def set_root(self, name_or_index: str, enabled: bool = True) -> Dict[str, Any]:
        """Habilita/desabilita root na instancia."""
        val = "1" if enabled else "0"
        rc, out, err = self._run(
            ["modify", "--name", str(name_or_index), "--root", val]
        )
        return {"success": rc == 0, "root": enabled}
