#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    LEVIATHAN VS - Orchestrator v1.0
    Automated workflow engine — chains LDPlayer + ADB + Frida + Bypass

    Workflows:
        full_intercept   - Launch emu → open app → bypass → hook everything → analyze
        quick_attach     - Attach to running app → bypass → intercept
        launch_emulator  - Start LDPlayer instance, wait, connect ADB
        open_app         - Launch app on emulator (with optional Frida attach)
        intercept_all    - Apply all interceptions (network, crypto, file I/O, etc.)
        analyze          - Collect all intercepted data and produce report
        stop_all         - Detach Frida, kill app, close emulator

    Author: ThiagoFrag / LEVIATHAN VS
    Version: 1.0.0
================================================================================
"""

import json
import logging
import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("leviathan.orchestrator")

# ── Module dir for output files ──
_BASE_DIR = Path(__file__).resolve().parent
_OUTPUT_DIR = _BASE_DIR / "output"

# ═══════════════════════════════════════════════════════════════════════
#  KNOWN APPS DATABASE — maps friendly names → package names
# ═══════════════════════════════════════════════════════════════════════
KNOWN_APPS: Dict[str, str] = {
    # ── Bancos BR ──
    "nubank": "com.nu.production",
    "nu": "com.nu.production",
    "roxinho": "com.nu.production",
    "itau": "com.itau",
    "itaú": "com.itau",
    "bradesco": "com.bradesco",
    "bb": "br.com.bb.android",
    "banco do brasil": "br.com.bb.android",
    "caixa": "br.com.gabba.Caixa",
    "inter": "br.com.intermedium",
    "banco inter": "br.com.intermedium",
    "c6": "com.c6bank.app",
    "c6 bank": "com.c6bank.app",
    "picpay": "com.picpay",
    "mercado pago": "com.mercadopago.wallet",
    "pagbank": "br.com.uol.ps.myaccount",
    "pagseguro": "br.com.uol.ps.myaccount",
    "next": "br.com.bradesco.next",
    "neon": "br.com.neon",
    "original": "br.com.original.bank",
    "santander": "com.santander.app",
    "safra": "com.safra.pocket",
    "btg": "com.btg.pactual.homebroker",
    "xp": "com.xpi.investor",
    "binance": "com.binance.dev",
    "coinbase": "com.coinbase.android",
    # ── Social / Comunicação ──
    "whatsapp": "com.whatsapp",
    "wpp": "com.whatsapp",
    "zap": "com.whatsapp",
    "whats": "com.whatsapp",
    "whatsapp business": "com.whatsapp.w4b",
    "telegram": "org.telegram.messenger",
    "tg": "org.telegram.messenger",
    "instagram": "com.instagram.android",
    "insta": "com.instagram.android",
    "ig": "com.instagram.android",
    "facebook": "com.facebook.katana",
    "fb": "com.facebook.katana",
    "messenger": "com.facebook.orca",
    "twitter": "com.twitter.android",
    "x": "com.twitter.android",
    "tiktok": "com.zhiliaoapp.musically",
    "snapchat": "com.snapchat.android",
    "snap": "com.snapchat.android",
    "discord": "com.discord",
    "signal": "org.thoughtcrime.securesms",
    "threads": "com.instagram.barcelona",
    "pinterest": "com.pinterest",
    "reddit": "com.reddit.frontpage",
    "linkedin": "com.linkedin.android",
    "kwai": "com.kwai.video",
    # ── Delivery / Transporte ──
    "ifood": "br.com.brainweb.ifood",
    "uber": "com.ubercab",
    "uber eats": "com.ubercab.eats",
    "99": "com.taxis99",
    "99 taxi": "com.taxis99",
    "rappi": "com.grability.rappi",
    "lalamove": "com.lalamove.huolala.client",
    "zé delivery": "com.ambev.ze",
    "ze delivery": "com.ambev.ze",
    # ── Streaming ──
    "spotify": "com.spotify.music",
    "netflix": "com.netflix.mediaclient",
    "youtube": "com.google.android.youtube",
    "yt": "com.google.android.youtube",
    "prime video": "com.amazon.avod.thirdpartyclient",
    "amazon prime": "com.amazon.avod.thirdpartyclient",
    "disney": "com.disney.disneyplus",
    "disney+": "com.disney.disneyplus",
    "hbo": "com.hbo.hbonow",
    "hbo max": "com.hbo.hbonow",
    "max": "com.hbo.hbonow",
    "globoplay": "com.globo.globotv",
    "twitch": "tv.twitch.android.app",
    "deezer": "deezer.android.app",
    "youtube music": "com.google.android.apps.youtube.music",
    "yt music": "com.google.android.apps.youtube.music",
    "crunchyroll": "com.crunchyroll.crunchyroid",
    # ── Compras ──
    "mercado livre": "com.mercadolibre",
    "ml": "com.mercadolibre",
    "shopee": "com.shopee.br",
    "amazon": "com.amazon.mShop.android.shopping",
    "aliexpress": "com.alibaba.aliexpresshd",
    "ali": "com.alibaba.aliexpresshd",
    "shein": "com.zzkko",
    "americanas": "com.b2w.americanas",
    "magalu": "com.luizalabs.mlapp",
    "magazine luiza": "com.luizalabs.mlapp",
    "casas bahia": "com.novapontocom.casasbahia",
    "olx": "com.olx.android.olx",
    "enjoei": "com.enjoei.app",
    # ── Games Populares ──
    "free fire": "com.dts.freefireth",
    "ff": "com.dts.freefireth",
    "garena": "com.dts.freefireth",
    "pubg": "com.tencent.ig",
    "cod mobile": "com.activision.callofduty.shooter",
    "codm": "com.activision.callofduty.shooter",
    "call of duty": "com.activision.callofduty.shooter",
    "genshin": "com.miHoYo.GenshinImpact",
    "genshin impact": "com.miHoYo.GenshinImpact",
    "roblox": "com.roblox.client",
    "minecraft": "com.mojang.minecraftpe",
    "brawl stars": "com.supercell.brawlstars",
    "clash royale": "com.supercell.clashroyale",
    "clash of clans": "com.supercell.clashofclans",
    "coc": "com.supercell.clashofclans",
    "among us": "com.innersloth.spacemafia",
    "fortnite": "com.epicgames.fortnite",
    "lol mobile": "com.riotgames.league.wildrift",
    "wild rift": "com.riotgames.league.wildrift",
    "valorant mobile": "com.riotgames.valorant",
    "stumble guys": "com.kitka.stumbleguys",
    "subway surfers": "com.kiloo.subwaysurf",
    "candy crush": "com.king.candycrushsaga",
    "coin master": "com.moonactive.coinmaster",
    "mobile legends": "com.mobile.legends",
    "mlbb": "com.mobile.legends",
    "honkai star rail": "com.HoYoverse.hkrpgoversea",
    "hsr": "com.HoYoverse.hkrpgoversea",
    "arena breakout": "com.proximabeta.mf.uamo",
    "fifa mobile": "com.ea.gp.fifamobile",
    "eafc mobile": "com.ea.gp.fifamobile",
    # ── Utilidades ──
    "chrome": "com.android.chrome",
    "gmail": "com.google.android.gm",
    "maps": "com.google.android.apps.maps",
    "google maps": "com.google.android.apps.maps",
    "waze": "com.waze",
    "duo": "com.google.android.apps.tachyon",
    "google meet": "com.google.android.apps.meetings",
    "zoom": "us.zoom.videomeetings",
    "teams": "com.microsoft.teams",
    "outlook": "com.microsoft.office.outlook",
    "onedrive": "com.microsoft.skydrive",
    "google drive": "com.google.android.apps.docs",
    "drive": "com.google.android.apps.docs",
    "notion": "notion.id",
    "trello": "com.trello",
    "slack": "com.Slack",
    "canva": "com.canva.editor",
    "duolingo": "com.duolingo",
    "chatgpt": "com.openai.chatgpt",
    "copilot": "com.microsoft.copilot",
    # ── Gov BR ──
    "gov.br": "br.gov.meugovbr",
    "gov": "br.gov.meugovbr",
    "meu gov": "br.gov.meugovbr",
    "carteira digital": "br.gov.meugovbr",
    "e-titulo": "br.jus.tse.eleitoral.etitulo",
    "etitulo": "br.jus.tse.eleitoral.etitulo",
    "sus": "br.gov.datasus.cnsdigital",
    "detran": "br.com.detransp",
    "caixa tem": "br.gov.caixa.tem",
    "fgts": "br.gov.caixa.fgts.trabalhador",
}


class Orchestrator:
    """
    High-level workflow engine that orchestrates LDConsole, ADB, Frida,
    and ProtectionBypass into automated pipelines.

    Usage:
        orch = Orchestrator(config_path="config_ldplayer.json")
        result = orch.full_intercept("com.example.app")
        report = orch.analyze()
    """

    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self._log: List[Dict[str, Any]] = []
        self._intercepted_data: Dict[str, List[Dict]] = {
            "network": [],
            "crypto": [],
            "file_io": [],
            "intents": [],
            "shared_prefs": [],
            "sqlite": [],
            "game": [],
            "custom": [],
        }
        self._state = {
            "emulator_running": False,
            "adb_connected": False,
            "frida_attached": False,
            "bypasses_applied": False,
            "intercepting": False,
            "target_package": None,
            "target_pid": None,
            "instance_name": None,
            "instance_index": 0,
            "start_time": None,
        }

        # Components (initialized lazily)
        self.ld: Any = None
        self.adb: Any = None
        self.frida: Any = None
        self.bypass: Any = None

        self._init_components()

    # ─────────────────────────────────────────────────────────────────────
    # INITIALIZATION
    # ─────────────────────────────────────────────────────────────────────

    def _load_config(self, path: Optional[str]) -> Dict:
        """Load config from JSON file."""
        if path and os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        # Try default location
        default = _BASE_DIR / "config_ldplayer.json"
        if default.is_file():
            with open(default, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    def _init_components(self):
        """Initialize all sub-components from config."""
        ld_cfg = self.config.get("ldplayer", {})
        adb_cfg = self.config.get("adb", {})
        frida_cfg = self.config.get("frida", {})

        try:
            from .ldconsole import LDConsole

            self.ld = LDConsole(
                install_path=ld_cfg.get("install_path", r"C:\LDPlayer\LDPlayer9"),
                ldconsole_name=ld_cfg.get("ldconsole", "ldconsole.exe"),
            )
            self._log_event("init", "LDConsole initialized")
        except Exception as e:
            logger.warning(f"LDConsole unavailable: {e}")

        try:
            from .adb_manager import ADBManager

            self.adb = ADBManager(
                adb_path=ld_cfg.get("adb_path", "adb"),
                host=adb_cfg.get("host", "127.0.0.1"),
                base_port=adb_cfg.get("base_port", 5555),
                timeout=adb_cfg.get("timeout", 30),
                retry_count=adb_cfg.get("retry_count", 3),
                retry_delay=adb_cfg.get("retry_delay", 2.0),
            )
            self._log_event("init", "ADBManager initialized")
        except Exception as e:
            logger.warning(f"ADBManager unavailable: {e}")

        try:
            from .frida_engine import FridaEngine

            self.frida = FridaEngine(
                adb_manager=self.adb,
                config=frida_cfg,
            )
            self._log_event("init", "FridaEngine initialized")
        except Exception as e:
            logger.warning(f"FridaEngine unavailable: {e}")

        try:
            from .protection_bypass import ProtectionBypass

            self.bypass = ProtectionBypass(
                frida_engine=self.frida,
                adb_manager=self.adb,
            )
            self._log_event("init", "ProtectionBypass initialized")
        except Exception as e:
            logger.warning(f"ProtectionBypass unavailable: {e}")

    def _log_event(self, category: str, message: str, data: Any = None):
        """Append to operation log."""
        entry = {
            "time": datetime.now().isoformat(),
            "category": category,
            "message": message,
        }
        if data is not None:
            entry["data"] = data
        self._log.append(entry)
        logger.info(f"[{category}] {message}")

    def _require(self, component_name: str):
        """Validate that a component is available."""
        comp = getattr(self, component_name, None)
        if comp is None:
            raise RuntimeError(
                f"Component '{component_name}' not available. "
                f"Check installation and config."
            )
        return comp

    # ═════════════════════════════════════════════════════════════════════
    #  CORE WORKFLOWS
    # ═════════════════════════════════════════════════════════════════════

    def full_intercept(
        self,
        package: str,
        instance: str = "0",
        bypasses: Optional[List[str]] = None,
        intercepts: Optional[List[str]] = None,
        wait_time: int = 5,
        auto_analyze: bool = True,
    ) -> Dict[str, Any]:
        """
        🚀 FULL PIPELINE: Launch emulator → open app → bypass → intercept → analyze.

        This is the main "do everything" command. Steps:
        1. Launch LDPlayer instance (if not running)
        2. Connect ADB
        3. Start Frida server
        4. Open the target app
        5. Attach Frida to the app
        6. Apply protection bypasses (SSL, root, emulator, frida, integrity)
        7. Start all interceptions (network, crypto, file I/O, intents, etc.)
        8. Wait for data collection
        9. Analyze and return report

        Args:
            package: App package name (e.g., "com.example.game")
            instance: LDPlayer instance name or index (default "0")
            bypasses: List of bypasses to apply (default: all)
            intercepts: List of intercepts to activate (default: all)
            wait_time: Seconds to wait for data collection after setup
            auto_analyze: Whether to auto-analyze after setup

        Returns:
            Complete operation report with all intercepted data.
        """
        self._state["start_time"] = datetime.now().isoformat()

        # Resolve friendly name → package name
        resolved = self.resolve_app(package)
        if resolved:
            if resolved != package:
                self._log_event("resolve", f"'{package}' → {resolved}")
            package = resolved
        else:
            return {
                "workflow": "full_intercept",
                "package": package,
                "success": False,
                "error": f"App não encontrado: '{package}'. Use o package name completo.",
            }

        self._state["target_package"] = package
        results = {
            "workflow": "full_intercept",
            "package": package,
            "steps": [],
            "success": True,
        }

        try:
            # Step 1: Launch Emulator
            step1 = self.launch_emulator(instance)
            results["steps"].append({"step": "launch_emulator", **step1})
            if not step1.get("success"):
                results["success"] = False
                results["error"] = "Failed to launch emulator"
                return results

            # Step 2: Connect ADB
            step2 = self.connect_adb()
            results["steps"].append({"step": "connect_adb", **step2})
            if not step2.get("success"):
                results["success"] = False
                results["error"] = "Failed to connect ADB"
                return results

            # Step 3: Start Frida Server
            step3 = self.start_frida_server()
            results["steps"].append({"step": "start_frida_server", **step3})

            # Step 4: Open App
            step4 = self.open_app(package)
            results["steps"].append({"step": "open_app", **step4})
            if not step4.get("success"):
                results["success"] = False
                results["error"] = f"Failed to open app: {package}"
                return results

            # Give app time to initialize
            time.sleep(2)

            # Step 5: Attach Frida
            step5 = self.attach_frida(package)
            results["steps"].append({"step": "attach_frida", **step5})
            if not step5.get("success"):
                results["success"] = False
                results["error"] = "Failed to attach Frida"
                return results

            # Step 6: Apply Bypasses
            step6 = self.apply_bypasses(bypasses)
            results["steps"].append({"step": "apply_bypasses", **step6})

            # Step 7: Start Interceptions
            step7 = self.start_interceptions(intercepts)
            results["steps"].append({"step": "start_interceptions", **step7})

            # Step 8: Wait for data
            self._log_event("collect", f"Collecting data for {wait_time}s...")
            time.sleep(wait_time)

            # Step 9: Analyze
            if auto_analyze:
                report = self.analyze()
                results["analysis"] = report

            self._log_event("workflow", "full_intercept completed successfully")
            return results

        except Exception as e:
            results["success"] = False
            results["error"] = str(e)
            self._log_event("error", f"full_intercept failed: {e}")
            return results

    def quick_attach(
        self,
        package: str,
        bypasses: Optional[List[str]] = None,
        intercepts: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        ⚡ Quick attach to an ALREADY RUNNING app.
        Skips emulator launch. Assumes ADB is connected and app is running.

        Steps:
        1. Verify ADB connection
        2. Start Frida server (if needed)
        3. Attach Frida to running app
        4. Apply bypasses
        5. Start interceptions
        """
        self._state["start_time"] = datetime.now().isoformat()

        # Resolve friendly name → package
        resolved = self.resolve_app(package)
        if resolved:
            package = resolved
        else:
            return {
                "workflow": "quick_attach",
                "package": package,
                "success": False,
                "error": f"App não encontrado: '{package}'",
            }

        self._state["target_package"] = package
        results = {"workflow": "quick_attach", "package": package, "steps": []}

        try:
            # Verify ADB
            if not self._state["adb_connected"]:
                step = self.connect_adb()
                results["steps"].append({"step": "connect_adb", **step})

            # Frida server
            step = self.start_frida_server()
            results["steps"].append({"step": "start_frida_server", **step})

            # Attach
            step = self.attach_frida(package)
            results["steps"].append({"step": "attach_frida", **step})

            # Bypasses
            step = self.apply_bypasses(bypasses)
            results["steps"].append({"step": "apply_bypasses", **step})

            # Interceptions
            step = self.start_interceptions(intercepts)
            results["steps"].append({"step": "start_interceptions", **step})

            results["success"] = True
            return results

        except Exception as e:
            results["success"] = False
            results["error"] = str(e)
            return results

    # ═════════════════════════════════════════════════════════════════════
    #  INDIVIDUAL OPERATIONS
    # ═════════════════════════════════════════════════════════════════════

    def launch_emulator(self, instance: str = "0") -> Dict[str, Any]:
        """
        Start LDPlayer instance and wait until it's ready.

        Args:
            instance: Instance name or index (e.g., "0", "LDPlayer")
        """
        self._require("ld")
        self._log_event("emulator", f"Launching instance: {instance}")

        # Check if already running
        if self.ld.is_running(instance):
            self._state["emulator_running"] = True
            self._state["instance_name"] = instance
            self._log_event("emulator", "Instance already running")
            return {"success": True, "message": "Already running", "was_running": True}

        # Launch
        result = self.ld.launch(instance)
        if result.get("success", True):
            # Wait for boot
            timeout = self.config.get("ldplayer", {}).get("launch_timeout", 60)
            self._log_event("emulator", f"Waiting up to {timeout}s for boot...")
            started = time.time()
            while time.time() - started < timeout:
                if self.ld.is_running(instance):
                    self._state["emulator_running"] = True
                    self._state["instance_name"] = instance
                    boot_time = round(time.time() - started, 1)
                    self._log_event("emulator", f"Booted in {boot_time}s")
                    # Wait a bit more for ADB to become available
                    time.sleep(3)
                    return {
                        "success": True,
                        "boot_time": boot_time,
                        "was_running": False,
                    }
                time.sleep(2)

            return {"success": False, "error": f"Boot timeout ({timeout}s)"}

        return {"success": False, "error": result.get("error", "Launch failed")}

    def connect_adb(self, instance_index: int = 0) -> Dict[str, Any]:
        """Connect ADB to the emulator."""
        self._require("adb")
        self._log_event("adb", f"Connecting ADB (instance {instance_index})")

        result = self.adb.auto_connect_ldplayer(instance_index)
        if "error" not in str(result.get("error", "")):
            self._state["adb_connected"] = True
            self._log_event("adb", "ADB connected")
            # Verify with device list
            devices = self.adb.list_devices()
            return {
                "success": True,
                "device": self.adb.get_current_device(),
                "devices_found": len(devices),
            }

        # Fallback: direct connect
        result = self.adb.connect()
        if result.get("success"):
            self._state["adb_connected"] = True
            return {"success": True, "device": self.adb.get_current_device()}

        return {"success": False, "error": "Could not connect ADB"}

    def start_frida_server(self) -> Dict[str, Any]:
        """Ensure Frida server is running on device."""
        self._require("frida")

        check = self.frida.check_frida_installed()
        if not check.get("frida_module"):
            return {
                "success": False,
                "error": "Frida not installed. Run: pip install frida frida-tools",
            }

        if self.frida.is_server_running():
            self._log_event("frida", "Server already running")
            return {"success": True, "message": "Already running"}

        result = self.frida.start_server()
        if result.get("success"):
            self._log_event("frida", "Server started")
        return result

    def open_app(self, package: str, activity: Optional[str] = None) -> Dict[str, Any]:
        """Launch an app on the emulator. Accepts friendly name or package."""
        self._require("adb")

        # Resolve friendly name
        resolved = self.resolve_app(package)
        if resolved:
            if resolved != package:
                self._log_event("resolve", f"'{package}' → {resolved}")
            package = resolved
        else:
            return {"success": False, "error": f"App não encontrado: '{package}'"}

        self._log_event("app", f"Opening: {package}")

        # Try via ADB
        result = self.adb.start_app(package, activity)
        if result.get("success", True):
            self._state["target_package"] = package
            time.sleep(1)

            # Get PID
            pid = self.adb.get_pid(package)
            if pid and pid > 0:
                self._state["target_pid"] = pid
                self._log_event("app", f"App running, PID: {pid}")
                return {"success": True, "package": package, "pid": pid}
            else:
                # PID might take a moment
                time.sleep(2)
                pid = self.adb.get_pid(package)
                self._state["target_pid"] = pid
                return {"success": True, "package": package, "pid": pid}

        return {"success": False, "error": f"Failed to start {package}"}

    def close_app(self, package: Optional[str] = None) -> Dict[str, Any]:
        """Force-stop the target app."""
        self._require("adb")
        pkg = package or self._state.get("target_package")
        if not pkg:
            return {"success": False, "error": "No target package"}

        result = self.adb.force_stop(pkg)
        self._state["target_pid"] = None
        self._log_event("app", f"Closed: {pkg}")
        return {"success": True, "package": pkg}

    def attach_frida(
        self, package: Optional[str] = None, spawn: bool = False
    ) -> Dict[str, Any]:
        """Attach Frida to the target app."""
        self._require("frida")
        pkg = package or self._state.get("target_package")
        if not pkg:
            return {"success": False, "error": "No target package specified"}

        self._log_event("frida", f"Attaching to: {pkg} (spawn={spawn})")

        if spawn:
            result = self.frida.spawn(pkg)
        else:
            # Try by package name first
            result = self.frida.attach(pkg)

        if result.get("success"):
            self._state["frida_attached"] = True
            self._state["target_pid"] = result.get("pid")
            self._log_event("frida", f"Attached! PID: {result.get('pid')}")
        else:
            self._log_event("frida", f"Attach failed: {result.get('error')}")

        return result

    def apply_bypasses(self, bypasses: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Apply protection bypasses. If no list given, applies all.

        Supported: ssl, root, emulator, frida, integrity, all
        """
        self._require("bypass")

        if not self._state.get("frida_attached"):
            return {
                "success": False,
                "error": "Frida not attached. Call attach_frida() first.",
            }

        # Default: from config or all
        if not bypasses:
            bypasses = self.config.get("protection_bypass", {}).get(
                "default_bypasses", ["ssl", "root", "emulator", "frida", "integrity"]
            )

        self._log_event("bypass", f"Applying bypasses: {bypasses}")
        results = {}

        if "all" in bypasses:
            result = self.bypass.apply_all_bypasses()
            results["all"] = result
        else:
            bypass_map = {
                "ssl": self.bypass.bypass_ssl_pinning,
                "root": self.bypass.bypass_root_detection,
                "emulator": self.bypass.bypass_emulator_detection,
                "frida": self.bypass.bypass_frida_detection,
                "integrity": self.bypass.bypass_integrity_checks,
            }
            for name in bypasses:
                fn = bypass_map.get(name)
                if fn:
                    try:
                        results[name] = fn()
                        self._log_event("bypass", f"  ✓ {name}")
                    except Exception as e:
                        results[name] = {"success": False, "error": str(e)}
                        self._log_event("bypass", f"  ✗ {name}: {e}")

        self._state["bypasses_applied"] = True
        success_count = sum(1 for v in results.values() if v.get("success", False))
        return {
            "success": success_count > 0,
            "applied": success_count,
            "total": len(results),
            "details": results,
        }

    def start_interceptions(
        self, intercepts: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Start intercepting app operations.

        Supported: network, crypto, file_io, intents, shared_prefs, sqlite, all
        """
        self._require("frida")

        if not self._state.get("frida_attached"):
            return {"success": False, "error": "Frida not attached"}

        if not intercepts:
            intercepts = [
                "network",
                "crypto",
                "file_io",
                "intents",
                "shared_prefs",
                "sqlite",
            ]

        self._log_event("intercept", f"Starting interceptions: {intercepts}")
        results = {}

        intercept_map = {
            "network": self.frida.intercept_http,
            "crypto": self.frida.intercept_crypto,
            "file_io": self.frida.intercept_file_io,
            "intents": self.frida.intercept_intents,
            "shared_prefs": self.frida.intercept_shared_prefs,
            "sqlite": self.frida.intercept_sqlite,
        }

        for name in intercepts:
            if name == "all":
                for n, fn in intercept_map.items():
                    try:
                        results[n] = fn()
                    except Exception as e:
                        results[n] = {"success": False, "error": str(e)}
                break
            fn = intercept_map.get(name)
            if fn:
                try:
                    results[name] = fn()
                    self._log_event("intercept", f"  ✓ {name}")
                except Exception as e:
                    results[name] = {"success": False, "error": str(e)}
                    self._log_event("intercept", f"  ✗ {name}: {e}")

        self._state["intercepting"] = True
        return {"success": True, "active": list(results.keys()), "details": results}

    def collect_data(self) -> Dict[str, Any]:
        """Collect all intercepted messages from Frida."""
        self._require("frida")

        messages = self.frida.get_messages(limit=0)  # 0 = all
        categorized = {
            "network": [],
            "crypto": [],
            "file_io": [],
            "intents": [],
            "shared_prefs": [],
            "sqlite": [],
            "game": [],
            "other": [],
        }

        for msg in messages:
            payload = msg.get("payload", {})
            if isinstance(payload, str):
                try:
                    payload = json.loads(payload)
                except (json.JSONDecodeError, TypeError):
                    payload = {"raw": payload}

            # Categorize by type/tag
            msg_type = ""
            if isinstance(payload, dict):
                msg_type = payload.get("type", payload.get("tag", "")).lower()

            if any(
                k in msg_type
                for k in [
                    "http",
                    "request",
                    "response",
                    "url",
                    "network",
                    "retrofit",
                    "grpc",
                ]
            ):
                categorized["network"].append(payload)
            elif any(
                k in msg_type
                for k in ["crypto", "cipher", "key", "digest", "aes", "rsa", "hmac"]
            ):
                categorized["crypto"].append(payload)
            elif any(k in msg_type for k in ["file", "open", "read", "write", "io"]):
                categorized["file_io"].append(payload)
            elif any(k in msg_type for k in ["intent", "broadcast", "activity"]):
                categorized["intents"].append(payload)
            elif any(k in msg_type for k in ["pref", "shared"]):
                categorized["shared_prefs"].append(payload)
            elif any(k in msg_type for k in ["sqlite", "sql", "db", "query"]):
                categorized["sqlite"].append(payload)
            elif any(k in msg_type for k in ["game", "unity", "cocos", "player_pref"]):
                categorized["game"].append(payload)
            else:
                categorized["other"].append(payload)

        # Merge with accumulated data
        for k, v in categorized.items():
            if k in self._intercepted_data:
                self._intercepted_data[k].extend(v)
            else:
                self._intercepted_data[k] = v

        total = sum(len(v) for v in categorized.values())
        self._log_event("collect", f"Collected {total} messages")
        return {
            "total_messages": total,
            "breakdown": {k: len(v) for k, v in categorized.items()},
            "data": categorized,
        }

    def analyze(self) -> Dict[str, Any]:
        """
        📊 Analyze all intercepted data and produce a comprehensive report.

        Returns a structured report with:
        - Summary stats
        - Network analysis (URLs, methods, status codes, domains)
        - Crypto analysis (algorithms, key sizes, operations)
        - File I/O analysis (files accessed, read/write patterns)
        - Security findings (hardcoded keys, unencrypted traffic, etc.)
        """
        # First collect latest data
        collection = self.collect_data()
        data = collection.get("data", {})

        report = {
            "timestamp": datetime.now().isoformat(),
            "target": self._state.get("target_package"),
            "pid": self._state.get("target_pid"),
            "duration": None,
            "summary": {},
            "network_analysis": {},
            "crypto_analysis": {},
            "file_io_analysis": {},
            "security_findings": [],
            "raw_counts": collection.get("breakdown", {}),
        }

        # Duration
        if self._state.get("start_time"):
            try:
                start = datetime.fromisoformat(self._state["start_time"])
                report["duration"] = str(datetime.now() - start)
            except (ValueError, TypeError):
                pass

        # ── Network Analysis ──
        net_data = data.get("network", []) + self._intercepted_data.get("network", [])
        if net_data:
            urls = []
            methods = {}
            domains = {}
            status_codes = {}

            for item in net_data:
                if isinstance(item, dict):
                    url = item.get("url", item.get("uri", ""))
                    method = item.get("method", "UNKNOWN")
                    status = str(item.get("status", item.get("status_code", "")))

                    if url:
                        urls.append(url)
                        # Extract domain
                        try:
                            from urllib.parse import urlparse

                            domain = urlparse(url).netloc
                            if domain:
                                domains[domain] = domains.get(domain, 0) + 1
                        except Exception:
                            pass

                    methods[method] = methods.get(method, 0) + 1
                    if status:
                        status_codes[status] = status_codes.get(status, 0) + 1

            report["network_analysis"] = {
                "total_requests": len(net_data),
                "unique_urls": len(set(urls)),
                "methods": methods,
                "domains": dict(sorted(domains.items(), key=lambda x: -x[1])[:20]),
                "status_codes": status_codes,
                "urls_sample": urls[:50],
            }

            # Security: unencrypted traffic
            http_urls = [u for u in urls if u.startswith("http://")]
            if http_urls:
                report["security_findings"].append(
                    {
                        "severity": "HIGH",
                        "type": "unencrypted_traffic",
                        "description": f"Found {len(http_urls)} HTTP (non-HTTPS) requests",
                        "samples": http_urls[:10],
                    }
                )

        # ── Crypto Analysis ──
        crypto_data = data.get("crypto", []) + self._intercepted_data.get("crypto", [])
        if crypto_data:
            algorithms = {}
            key_sizes = {}
            operations = {}

            for item in crypto_data:
                if isinstance(item, dict):
                    algo = item.get("algorithm", item.get("cipher", "unknown"))
                    algorithms[algo] = algorithms.get(algo, 0) + 1

                    ks = item.get("key_size", item.get("keySize"))
                    if ks:
                        key_sizes[str(ks)] = key_sizes.get(str(ks), 0) + 1

                    op = item.get("operation", item.get("mode", "unknown"))
                    operations[op] = operations.get(op, 0) + 1

            report["crypto_analysis"] = {
                "total_operations": len(crypto_data),
                "algorithms": algorithms,
                "key_sizes": key_sizes,
                "operations": operations,
            }

            # Security: weak crypto
            weak = [
                a
                for a in algorithms
                if any(w in a.upper() for w in ["DES", "RC4", "MD5", "SHA1", "ECB"])
            ]
            if weak:
                report["security_findings"].append(
                    {
                        "severity": "MEDIUM",
                        "type": "weak_crypto",
                        "description": f"Weak cryptographic algorithms detected: {', '.join(weak)}",
                    }
                )

        # ── File I/O Analysis ──
        file_data = data.get("file_io", []) + self._intercepted_data.get("file_io", [])
        if file_data:
            files_accessed = set()
            read_count = 0
            write_count = 0

            for item in file_data:
                if isinstance(item, dict):
                    path = item.get("path", item.get("file", ""))
                    if path:
                        files_accessed.add(path)
                    op = item.get("operation", "").lower()
                    if "read" in op:
                        read_count += 1
                    elif "write" in op:
                        write_count += 1

            report["file_io_analysis"] = {
                "total_operations": len(file_data),
                "unique_files": len(files_accessed),
                "reads": read_count,
                "writes": write_count,
                "files_sample": list(files_accessed)[:30],
            }

            # Security: sensitive file access
            sensitive_patterns = [
                "/data/data/",
                "/sdcard/",
                ".db",
                ".sqlite",
                "shared_prefs",
                "password",
                "token",
                "key",
            ]
            suspicious = [
                f
                for f in files_accessed
                if any(p in f.lower() for p in sensitive_patterns)
            ]
            if suspicious:
                report["security_findings"].append(
                    {
                        "severity": "INFO",
                        "type": "sensitive_file_access",
                        "description": f"Access to {len(suspicious)} potentially sensitive files",
                        "samples": list(suspicious)[:10],
                    }
                )

        # ── Summary ──
        report["summary"] = {
            "total_events": sum(collection.get("breakdown", {}).values()),
            "network_requests": len(net_data) if net_data else 0,
            "crypto_operations": len(crypto_data) if crypto_data else 0,
            "file_operations": len(file_data) if file_data else 0,
            "security_findings": len(report["security_findings"]),
            "severity_breakdown": {},
        }

        # Count by severity
        for finding in report["security_findings"]:
            sev = finding.get("severity", "INFO")
            report["summary"]["severity_breakdown"][sev] = (
                report["summary"]["severity_breakdown"].get(sev, 0) + 1
            )

        self._log_event("analyze", f"Report: {report['summary']}")
        return report

    # ═════════════════════════════════════════════════════════════════════
    #  UTILITY OPERATIONS
    # ═════════════════════════════════════════════════════════════════════

    def scan_protections(self, package: Optional[str] = None) -> Dict[str, Any]:
        """Scan the target app for protection mechanisms."""
        self._require("bypass")
        pkg = package or self._state.get("target_package")
        return self.bypass.scan_protections(pkg)

    def scan_and_bypass(self) -> Dict[str, Any]:
        """Full auto: scan protections + apply all bypasses."""
        self._require("bypass")
        return self.bypass.scan_and_bypass_all()

    def list_apps(self, third_party: bool = True) -> List[str]:
        """List installed apps on the emulator."""
        self._require("adb")
        return self.adb.list_packages(third_party=third_party)

    def resolve_app(self, name_or_package: str) -> Optional[str]:
        """
        Smart app resolver. Accepts friendly name OR package name.

        Resolution order:
        1. If it already looks like a package name (has dots) → return as-is
        2. Check KNOWN_APPS database (nubank → com.nu.production)
        3. Search installed packages by keyword
        4. Get app labels via ADB and match
        5. Fuzzy match against known apps

        Returns the package name or None if not found.
        """
        name = name_or_package.strip()
        if not name:
            return None

        # 1. Already a package name?
        if re.match(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$", name, re.IGNORECASE):
            return name

        # 2. Known apps database (exact match, case-insensitive)
        name_lower = name.lower().strip()
        if name_lower in KNOWN_APPS:
            pkg = KNOWN_APPS[name_lower]
            self._log_event("resolve", f"'{name}' → {pkg} (known database)")
            return pkg

        # 3. Search installed packages by keyword
        try:
            packages = self.adb.list_packages(third_party=True)
            # Direct substring match in package name
            matches = [p for p in packages if name_lower in p.lower()]
            if len(matches) == 1:
                self._log_event("resolve", f"'{name}' → {matches[0]} (package search)")
                return matches[0]
            if matches:
                self._log_event(
                    "resolve", f"'{name}' → {len(matches)} candidates from packages"
                )
                # Return best match (shortest = most specific)
                return min(matches, key=len)
        except Exception:
            pass

        # 4. Get app labels via ADB cmd package + dumpsys
        try:
            rc, out, _ = self.adb.shell(
                f"cmd package query-activities -a android.intent.action.MAIN -c android.intent.category.LAUNCHER"
            )
            if rc == 0 and out:
                # Parse output for package names, but also try dumpsys for labels
                pass
        except Exception:
            pass

        # 5. Fuzzy match against known apps database
        best_score = 0
        best_pkg = None
        for known_name, pkg in KNOWN_APPS.items():
            # Simple word overlap similarity
            name_words = set(name_lower.split())
            known_words = set(known_name.lower().split())

            # Check if name is contained in known_name or vice versa
            if name_lower in known_name or known_name in name_lower:
                score = 0.8
            else:
                # Word overlap
                overlap = name_words & known_words
                if overlap:
                    score = len(overlap) / max(len(name_words), len(known_words))
                else:
                    # Character-level similarity
                    common = sum(1 for c in name_lower if c in known_name)
                    score = common / max(len(name_lower), len(known_name)) * 0.5

            if score > best_score:
                best_score = score
                best_pkg = pkg

        if best_score >= 0.5 and best_pkg:
            self._log_event(
                "resolve", f"'{name}' → {best_pkg} (fuzzy, score={best_score:.2f})"
            )
            return best_pkg

        self._log_event("resolve", f"'{name}' → not found")
        return None

    def find_app(self, keyword: str) -> List[str]:
        """
        Search installed apps by keyword. Also checks known apps database.
        Returns list of matching package names.
        """
        self._require("adb")
        results = []
        keyword_lower = keyword.lower().strip()

        # Check known database
        for name, pkg in KNOWN_APPS.items():
            if keyword_lower in name or keyword_lower in pkg.lower():
                if pkg not in results:
                    results.append(pkg)

        # Search installed packages
        try:
            packages = self.adb.list_packages(third_party=True)
            for p in packages:
                if keyword_lower in p.lower() and p not in results:
                    results.append(p)
        except Exception:
            pass

        return results

    def app_info(self, package: Optional[str] = None) -> Dict[str, Any]:
        """Get detailed info about an app."""
        self._require("adb")
        pkg = package or self._state.get("target_package")
        if not pkg:
            return {"error": "No package specified"}
        return self.adb.get_package_info(pkg)

    def screenshot(self, save_path: Optional[str] = None) -> Dict[str, Any]:
        """Take a screenshot of the emulator."""
        self._require("adb")
        if not save_path:
            _OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            save_path = str(_OUTPUT_DIR / f"screenshot_{ts}.png")
        return self.adb.screenshot(save_path)

    def logcat(self, lines: int = 100, package: Optional[str] = None) -> str:
        """Get logcat output."""
        self._require("adb")
        pkg = package or self._state.get("target_package")
        if pkg:
            return self.adb.logcat_by_package(pkg, lines=lines)
        return self.adb.logcat(lines=lines)

    def enum_classes(self, filter_str: str = "") -> Dict[str, Any]:
        """Enumerate loaded Java classes."""
        self._require("frida")
        return self.frida.enumerate_classes(filter_str)

    def hook(
        self,
        class_name: str,
        method_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Hook a Java class or method."""
        self._require("frida")
        if method_name:
            return self.frida.hook_method(class_name, method_name)
        return self.frida.hook_class(class_name)

    def inject_script(self, script_name: str) -> Dict[str, Any]:
        """
        Inject one of the pre-built Frida scripts.
        Available: ssl_bypass, root_bypass, emulator_bypass, frida_bypass,
                   network_interceptor, crypto_interceptor, universal_bypass,
                   game_inspector
        """
        self._require("frida")
        # Map friendly names to file paths
        scripts_dir = _BASE_DIR / "frida_scripts"
        name_map = {
            "ssl": "ssl_bypass.js",
            "ssl_bypass": "ssl_bypass.js",
            "root": "root_bypass.js",
            "root_bypass": "root_bypass.js",
            "emulator": "emulator_bypass.js",
            "emulator_bypass": "emulator_bypass.js",
            "frida": "frida_bypass.js",
            "frida_bypass": "frida_bypass.js",
            "network": "network_interceptor.js",
            "network_interceptor": "network_interceptor.js",
            "crypto": "crypto_interceptor.js",
            "crypto_interceptor": "crypto_interceptor.js",
            "universal": "universal_bypass.js",
            "universal_bypass": "universal_bypass.js",
            "game": "game_inspector.js",
            "game_inspector": "game_inspector.js",
        }

        filename = name_map.get(script_name.lower(), f"{script_name}.js")
        path = scripts_dir / filename
        if not path.is_file():
            return {"success": False, "error": f"Script not found: {path}"}

        return self.frida.inject_script_file(str(path), name=script_name)

    # ═════════════════════════════════════════════════════════════════════
    #  CLEANUP & STATE
    # ═════════════════════════════════════════════════════════════════════

    def stop_all(self, close_emulator: bool = False) -> Dict[str, Any]:
        """Detach Frida, stop app, optionally close emulator."""
        results = {}

        # Detach Frida
        if self.frida and self._state.get("frida_attached"):
            try:
                self.frida.unload_all_scripts()
                self.frida.detach()
                self._state["frida_attached"] = False
                self._state["intercepting"] = False
                results["frida_detached"] = True
            except Exception as e:
                results["frida_detach_error"] = str(e)

        # Stop app
        if self.adb and self._state.get("target_package"):
            try:
                self.adb.force_stop(self._state["target_package"])
                results["app_stopped"] = True
            except Exception as e:
                results["app_stop_error"] = str(e)

        # Close emulator
        if close_emulator and self.ld and self._state.get("instance_name"):
            try:
                self.ld.quit(self._state["instance_name"])
                self._state["emulator_running"] = False
                results["emulator_closed"] = True
            except Exception as e:
                results["emulator_close_error"] = str(e)

        self._log_event("cleanup", "stop_all executed", results)
        return results

    def get_state(self) -> Dict[str, Any]:
        """Return current orchestrator state."""
        return {
            **self._state,
            "log_entries": len(self._log),
            "intercepted_data_counts": {
                k: len(v) for k, v in self._intercepted_data.items()
            },
        }

    def get_log(self, last_n: int = 50) -> List[Dict]:
        """Return operation log."""
        return self._log[-last_n:] if last_n > 0 else self._log

    def save_report(self, filepath: Optional[str] = None) -> str:
        """Save the analysis report to a JSON file."""
        report = self.analyze()
        if not filepath:
            _OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            pkg = self._state.get("target_package", "unknown")
            filepath = str(_OUTPUT_DIR / f"report_{pkg}_{ts}.json")

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)

        self._log_event("report", f"Saved to: {filepath}")
        return filepath

    def reset(self):
        """Reset all state and collected data."""
        self._intercepted_data = {k: [] for k in self._intercepted_data}
        self._log.clear()
        self._state = {
            "emulator_running": False,
            "adb_connected": False,
            "frida_attached": False,
            "bypasses_applied": False,
            "intercepting": False,
            "target_package": None,
            "target_pid": None,
            "instance_name": None,
            "instance_index": 0,
            "start_time": None,
        }
        self._log_event("reset", "Orchestrator reset")
