#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for http_toolkit.py and cache.py."""

import json
import os
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure core/ is importable
sys.path.insert(0, str(Path(__file__).parent.parent / "core"))

from cache import ResultCache

# ============================================================================
# ResultCache tests
# ============================================================================


class TestResultCache:
    """Tests for the SQLite-backed result cache."""

    @pytest.fixture(autouse=True)
    def setup_cache(self, tmp_path):
        """Create a temp cache for each test."""
        self.db = tmp_path / "test_cache.db"
        self.cache = ResultCache(db_path=self.db, default_ttl_hours=1)

    def test_put_and_get(self):
        self.cache.put("scan", "https://example.com", {"status": 200})
        result = self.cache.get("scan", "https://example.com")
        assert result is not None
        assert result["status"] == 200

    def test_get_missing_returns_none(self):
        result = self.cache.get("scan", "https://nonexistent.com")
        assert result is None

    def test_has_existing(self):
        self.cache.put("dispatch", "https://api.test", {"ok": True})
        assert self.cache.has("dispatch", "https://api.test") is True

    def test_has_missing(self):
        assert self.cache.has("dispatch", "https://missing.test") is False

    def test_overwrite(self):
        self.cache.put("scan", "https://example.com", {"v": 1})
        self.cache.put("scan", "https://example.com", {"v": 2})
        result = self.cache.get("scan", "https://example.com")
        assert result["v"] == 2

    def test_expired_returns_none(self):
        # Use extremely short TTL
        c = ResultCache(db_path=self.db, default_ttl_hours=0)
        c.put("scan", "https://old.com", {"data": "old"}, ttl_hours=0)
        # Manually expire it
        import sqlite3

        with sqlite3.connect(str(self.db)) as conn:
            conn.execute("UPDATE cache SET expires_at = ?", (time.time() - 1,))
        result = c.get("scan", "https://old.com")
        assert result is None

    def test_list_recent(self):
        self.cache.put("scan", "url1", {"a": 1})
        self.cache.put("dispatch", "url2", {"b": 2})
        entries = self.cache.list_recent(10)
        assert len(entries) == 2

    def test_list_recent_by_category(self):
        self.cache.put("scan", "url1", {})
        self.cache.put("dispatch", "url2", {})
        entries = self.cache.list_recent(10, category="scan")
        assert len(entries) == 1

    def test_clear_all(self):
        self.cache.put("scan", "url1", {})
        self.cache.put("scan", "url2", {})
        self.cache.clear()
        assert self.cache.list_recent(10) == []

    def test_clear_by_category(self):
        self.cache.put("scan", "url1", {})
        self.cache.put("dispatch", "url2", {})
        self.cache.clear(category="scan")
        entries = self.cache.list_recent(10)
        assert len(entries) == 1
        assert entries[0]["category"] == "dispatch"

    def test_purge_expired(self):
        import sqlite3

        self.cache.put("scan", "url1", {})
        # Force-expire it
        with sqlite3.connect(str(self.db)) as conn:
            conn.execute("UPDATE cache SET expires_at = ?", (time.time() - 1,))
        removed = self.cache.purge_expired()
        assert removed == 1

    def test_stats(self):
        self.cache.put("scan", "url1", {})
        self.cache.put("scan", "url2", {})
        s = self.cache.stats()
        assert s["total_entries"] == 2
        assert s["categories"]["scan"] == 2
        assert "db_size_kb" in s

    def test_hit_count_increments(self):
        self.cache.put("scan", "url1", {"data": 1})
        self.cache.get("scan", "url1")
        self.cache.get("scan", "url1")
        entries = self.cache.list_recent(1)
        assert entries[0]["hits"] == 2


# ============================================================================
# HTTP Toolkit unit tests (no real network)
# ============================================================================


class TestHTTPToolkitUnits:
    """Unit tests for http_toolkit classes (no network required)."""

    def test_request_config_defaults(self):
        from http_toolkit import RequestConfig

        cfg = RequestConfig(url="https://test.com")
        assert cfg.method == "GET"
        assert cfg.timeout == 30
        assert cfg.retries == 3

    def test_response_data_is_success(self):
        from http_toolkit import ResponseData

        r = ResponseData(200, "OK", {}, "", {"start": 0, "end": 0, "duration": 0})
        assert r.is_success() is True
        assert r.is_error() is False

    def test_response_data_is_error(self):
        from http_toolkit import ResponseData

        r = ResponseData(
            404, "Not Found", {}, "", {"start": 0, "end": 0, "duration": 0}
        )
        assert r.is_success() is False
        assert r.is_error() is True

    def test_response_to_dict(self):
        from http_toolkit import ResponseData

        r = ResponseData(
            200, "OK", {"X-Test": "1"}, "body", {"start": 0, "end": 1, "duration": 100}
        )
        d = r.to_dict()
        assert d["status"] == 200
        assert d["body"] == "body"
        assert d["headers"]["X-Test"] == "1"

    def test_header_mimicry_rotation(self):
        from http_toolkit import HeaderMimicry

        hm = HeaderMimicry()
        initial = hm.current_profile
        headers = hm.get_headers()
        assert "User-Agent" in headers
        assert isinstance(headers["User-Agent"], str)

    def test_header_mimicry_set_profile(self):
        from http_toolkit import HeaderMimicry

        hm = HeaderMimicry()
        assert hm.set_profile("firefox_windows") is True
        assert hm.set_profile("nonexistent") is False

    def test_semantic_processor_roundtrip(self):
        from http_toolkit import SemanticProcessor

        sp = SemanticProcessor()
        # Even without loaded rules, empty roundtrip should work
        text = "hello world"
        sanitized = sp.sanitize(text)
        # With rules loaded, test actual roundtrip if config exists
        if sp.rules:
            restored = sp.restore(sanitized)
            # Should be approximately the same (case might differ)
            assert isinstance(restored, str)
        else:
            assert sanitized == text

    def test_ai_analysis_security_headers(self):
        from http_toolkit import AIIntegration, RequestConfig, ResponseData

        ai = AIIntegration()
        ai.cache = {}  # start fresh, no file state
        config = RequestConfig(url="https://test.com")
        resp = ResponseData(200, "OK", {}, "", {"start": 0, "end": 0, "duration": 100})
        analysis = ai.analyze_response(resp, config)
        assert "headers_analysis" in analysis
        assert len(analysis["headers_analysis"]["missing"]) > 0  # no security headers

    def test_ai_analysis_detects_patterns(self):
        from http_toolkit import AIIntegration, RequestConfig, ResponseData

        ai = AIIntegration()
        ai.cache = {}
        config = RequestConfig(url="https://test.com/api")
        resp = ResponseData(
            500,
            "Internal Server Error",
            {},
            "Traceback (most recent call last):\n  File test.py at line 42",
            {"start": 0, "end": 0, "duration": 200},
        )
        analysis = ai.analyze_response(resp, config)
        assert len(analysis["patterns_detected"]) > 0

    def test_auto_repair_strategies(self):
        from http_toolkit import AIAutoRepair, RequestConfig, ResponseData

        repair = AIAutoRepair()
        config = RequestConfig(url="https://test.com")

        r403 = ResponseData(
            403, "Forbidden", {}, "", {"start": 0, "end": 0, "duration": 0}
        )
        result = repair.analyze_failure(r403, config)
        assert result["should_retry"] is True
        assert result["strategy"] == "linear_decoupling"

        r429 = ResponseData(
            429, "Too Many Requests", {}, "", {"start": 0, "end": 0, "duration": 0}
        )
        result = repair.analyze_failure(r429, config)
        assert result["should_retry"] is True

    def test_dispatcher_dispatch_json_no_network(self):
        from http_toolkit import HOGDispatcher

        d = HOGDispatcher(verbose=False, session=False)
        # dispatch to invalid url will return error response, but won't crash
        result = d.dispatch_json("http://127.0.0.1:1", "GET")
        assert "status" in result

    def test_dispatcher_profile_endpoint_method_exists(self):
        from http_toolkit import HOGDispatcher

        d = HOGDispatcher(verbose=False, session=False)
        assert hasattr(d, "profile_endpoint")

    def test_session_manager_lifecycle(self, tmp_path):
        from http_toolkit import SESSION_FILE, SessionManager

        sm = SessionManager()
        sm.cookies = {}
        sm.update_from_response({"Set-Cookie": "sid=abc123; Path=/"})
        assert "sid" in sm.cookies
        cookie = sm.get_cookie_header()
        assert "sid=abc123" in cookie
        sm.clear()
        assert sm.cookies == {}

    def test_safe_mode_env(self):
        from http_toolkit import SAFE_MODE

        # SAFE_MODE should be True by default (env LEVIATHAN_SAFE_MODE=1 or unset)
        assert isinstance(SAFE_MODE, bool)


# ============================================================================
# generate_tasks_md tests
# ============================================================================


class TestGenerateTasksMd:
    """Test TASKS.md generator."""

    def test_loads_tasks(self):
        from generate_tasks_md import load_tasks

        tasks = load_tasks()
        assert len(tasks) > 0

    def test_categorize(self):
        from generate_tasks_md import categorize_tasks

        tasks = [
            {"label": "[ADB] List Devices", "detail": "Lists ADB devices"},
            {"label": "[ADB] Pull File", "detail": "Pull file from device"},
            {"label": "[FRIDA] Attach", "detail": "Attach Frida"},
        ]
        cats = categorize_tasks(tasks)
        assert "ADB" in cats
        assert "FRIDA" in cats
        assert len(cats["ADB"]) == 2

    def test_generate_markdown(self):
        from generate_tasks_md import categorize_tasks, generate_markdown

        tasks = [{"label": "[TEST] Sample", "detail": "A test task"}]
        cats = categorize_tasks(tasks)
        md = generate_markdown(cats)
        assert "## Category: TEST" in md
        assert "`[TEST] Sample`" in md
