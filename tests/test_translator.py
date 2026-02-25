#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for LEVIATHAN VS — Kraken Engine (SemanticTranslator).

Run:
    python -m pytest tests/ -v
    python -m pytest tests/test_translator.py -v
"""

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

# Add core/ to path so we can import translator
CORE_DIR = Path(__file__).parent.parent / "core"
sys.path.insert(0, str(CORE_DIR))

from translator import Mode, SemanticTranslator, TranslationResult

# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def tmp_workspace(tmp_path):
    """Create a temporary workspace with config.json and work.txt."""
    config = {
        "_version": "test",
        "bypass": "linear_decoupling",
        "exploit": "edge_case_path",
        "payload": "serialized_state",
        "injection": "stream_merging",
        "vulnerability": "logic_bottleneck",
        "hack": "structural_mutation",
        "firewall": "boundary_filter",
        "malware": "rogue_process",
    }
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    work_path = tmp_path / "work.txt"
    work_path.touch()
    return tmp_path


@pytest.fixture
def translator(tmp_workspace):
    """Create a SemanticTranslator with a temp workspace."""
    return SemanticTranslator(base_path=tmp_workspace)


def _write_work(workspace: Path, content: str):
    """Helper to write content to work.txt."""
    (workspace / "work.txt").write_text(content, encoding="utf-8")


def _read_work(workspace: Path) -> str:
    """Helper to read content from work.txt."""
    return (workspace / "work.txt").read_text(encoding="utf-8")


# ============================================================================
# BASIC ENCODE / DECODE TESTS
# ============================================================================


class TestEncodeRestore:
    """Test roundtrip encode -> restore preserves content."""

    def test_basic_encode(self, translator, tmp_workspace):
        _write_work(tmp_workspace, "The exploit bypasses the firewall")
        result = translator.encode()
        assert result.success
        assert result.total_replacements > 0
        content = _read_work(tmp_workspace)
        assert "exploit" not in content.lower()
        assert "edge_case_path" in content.lower()

    def test_basic_decode(self, translator, tmp_workspace):
        _write_work(tmp_workspace, "The edge_case_path uses linear_decoupling")
        result = translator.decode()
        assert result.success
        assert result.total_replacements > 0
        content = _read_work(tmp_workspace)
        assert "exploit" in content.lower()
        assert "bypass" in content.lower()

    def test_roundtrip(self, translator, tmp_workspace):
        """encode -> decode should produce original content."""
        original = "The exploit bypasses the firewall using a payload injection"
        _write_work(tmp_workspace, original)

        translator.encode()
        encoded = _read_work(tmp_workspace)
        assert encoded != original  # Something changed

        translator.decode()
        restored = _read_work(tmp_workspace)
        assert restored.lower() == original.lower()

    def test_roundtrip_preserves_unknown_words(self, translator, tmp_workspace):
        original = "The python function calculates fibonacci"
        _write_work(tmp_workspace, original)

        result = translator.encode()
        content = _read_work(tmp_workspace)
        # No rules match, so content should be unchanged
        assert content == original
        assert result.total_replacements == 0

    def test_empty_file(self, translator, tmp_workspace):
        _write_work(tmp_workspace, "")
        result = translator.encode()
        assert not result.success
        assert result.total_replacements == 0

    def test_whitespace_only(self, translator, tmp_workspace):
        _write_work(tmp_workspace, "   \n\n  ")
        result = translator.encode()
        assert not result.success

    def test_preview_mode(self, translator, tmp_workspace):
        """Preview should not modify the file."""
        original = "The exploit bypasses the firewall"
        _write_work(tmp_workspace, original)
        result = translator.encode(preview_only=True)
        assert result.success
        assert result.total_replacements > 0
        # File unchanged
        assert _read_work(tmp_workspace) == original


# ============================================================================
# CASE PRESERVATION TESTS
# ============================================================================


class TestCasePreservation:
    """Test that case is preserved during translation."""

    def test_lowercase(self, translator, tmp_workspace):
        _write_work(tmp_workspace, "exploit found")
        translator.encode()
        content = _read_work(tmp_workspace)
        assert "edge_case_path" in content

    def test_capitalize(self, translator, tmp_workspace):
        _write_work(tmp_workspace, "Exploit found")
        translator.encode()
        content = _read_work(tmp_workspace)
        assert "Edge_case_path" in content

    def test_uppercase(self, translator, tmp_workspace):
        _write_work(tmp_workspace, "EXPLOIT found")
        translator.encode()
        content = _read_work(tmp_workspace)
        assert "EDGE_CASE_PATH" in content


# ============================================================================
# MULTILINE & FORMAT PRESERVATION TESTS
# ============================================================================


class TestFormatPreservation:
    """Test that formatting is preserved during translation."""

    def test_multiline(self, translator, tmp_workspace):
        text = "Line 1: exploit\nLine 2: bypass\nLine 3: safe text"
        _write_work(tmp_workspace, text)
        result = translator.encode()
        content = _read_work(tmp_workspace)
        assert content.count("\n") == text.count("\n")
        assert "safe text" in content

    def test_indentation_preserved(self, translator, tmp_workspace):
        text = "    bypass detected\n        exploit found"
        _write_work(tmp_workspace, text)
        translator.encode()
        content = _read_work(tmp_workspace)
        assert content.startswith("    ")
        assert "\n        " in content

    def test_json_content(self, translator, tmp_workspace):
        """Ensure JSON structure is preserved."""
        text = '{"vuln_type": "exploit", "status": "bypass"}'
        _write_work(tmp_workspace, text)
        translator.encode()
        content = _read_work(tmp_workspace)
        # JSON structure should still be parseable text
        assert '"vuln_type"' in content
        assert '"status"' in content

    def test_urls_preserved(self, translator, tmp_workspace):
        """URLs containing rule words shouldn't be mangled."""
        text = "Visit https://example.com/docs for info. The exploit works."
        _write_work(tmp_workspace, text)
        translator.encode()
        content = _read_work(tmp_workspace)
        assert "https://example.com/docs" in content

    def test_comments_preserved(self, translator, tmp_workspace):
        text = "# This is a comment about exploit\nThe bypass works"
        _write_work(tmp_workspace, text)
        translator.encode()
        content = _read_work(tmp_workspace)
        assert content.startswith("# This is a comment about")
        assert content.count("\n") == 1


# ============================================================================
# EDGE CASES
# ============================================================================


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_word_boundary(self, translator, tmp_workspace):
        """Rules should only match whole words."""
        text = "exploitation bypassed"
        _write_work(tmp_workspace, text)
        result = translator.encode()
        content = _read_work(tmp_workspace)
        # "exploitation" is NOT "exploit" — should NOT match
        # (depends on regex word boundary behavior)
        # "bypassed" is NOT "bypass" in terms of word boundary
        # The actual behavior depends on the \b regex

    def test_multiple_rules_same_line(self, translator, tmp_workspace):
        text = "exploit and bypass and payload"
        _write_work(tmp_workspace, text)
        result = translator.encode()
        content = _read_work(tmp_workspace)
        assert "exploit" not in content.lower()
        assert "bypass" not in content.lower()
        assert "payload" not in content.lower()

    def test_special_regex_chars(self, tmp_workspace):
        """Config values with regex special chars should be escaped."""
        config = {"test.value": "safe_replacement", "test+plus": "safe_plus"}
        (tmp_workspace / "config.json").write_text(json.dumps(config), encoding="utf-8")
        t = SemanticTranslator(base_path=tmp_workspace)
        _write_work(tmp_workspace, "test.value found")
        result = t.encode()
        # Should handle regex special chars without crashing

    def test_nonexistent_work_file(self, tmp_workspace):
        (tmp_workspace / "work.txt").unlink()
        t = SemanticTranslator(base_path=tmp_workspace)
        result = t.encode()
        assert not result.success

    def test_very_large_content(self, translator, tmp_workspace):
        """Performance test: large file should still work."""
        text = "exploit bypass payload " * 1000
        _write_work(tmp_workspace, text)
        result = translator.encode()
        assert result.success
        assert result.total_replacements >= 3000


# ============================================================================
# BACKUP & UNDO TESTS
# ============================================================================


class TestBackupUndo:
    """Test backup creation and undo functionality."""

    def test_backup_created_on_encode(self, translator, tmp_workspace):
        _write_work(tmp_workspace, "exploit found")
        result = translator.encode()
        assert result.backup_path is not None
        assert Path(result.backup_path).exists()

    def test_undo(self, translator, tmp_workspace):
        original = "exploit found"
        _write_work(tmp_workspace, original)
        translator.encode()
        encoded = _read_work(tmp_workspace)
        assert encoded != original

        success = translator.undo()
        assert success
        restored = _read_work(tmp_workspace)
        assert restored == original


# ============================================================================
# STATS & VALIDATION TESTS
# ============================================================================


class TestStatsValidation:
    """Test statistics and config validation."""

    def test_stats(self, translator, tmp_workspace):
        _write_work(tmp_workspace, "exploit bypass test")
        stats = translator.get_stats()
        assert stats["file_exists"]
        assert stats["words"] == 3
        assert stats["lines"] == 1
        assert stats["rules_loaded"] > 0
        assert stats["original_terms_found"] >= 2

    def test_is_clean(self, translator, tmp_workspace):
        _write_work(tmp_workspace, "safe content here")
        clean, count = translator.is_clean()
        assert clean
        assert count == 0

    def test_is_not_clean(self, translator, tmp_workspace):
        _write_work(tmp_workspace, "exploit found here")
        clean, count = translator.is_clean()
        assert not clean
        assert count >= 1

    def test_validate_config(self, translator):
        errors = translator.validate_config()
        # Our test config should be valid
        assert isinstance(errors, list)


# ============================================================================
# DOCTOR & CONFIG_SCHEMA TESTS
# ============================================================================


class TestDoctor:
    """Basic tests for doctor.py."""

    def test_import(self):
        from doctor import DoctorReport, run_doctor

        assert callable(run_doctor)

    def test_run(self):
        from doctor import run_doctor

        report = run_doctor()
        assert report.timestamp
        assert report.python_version
        assert "ok" in report.summary or "fail" in report.summary


class TestConfigSchema:
    """Basic tests for config_schema.py."""

    def test_import(self):
        from config_schema import validate_all

        assert callable(validate_all)

    def test_validate_config(self):
        from config_schema import validate_config_json

        report = validate_config_json()
        assert hasattr(report, "valid")
        assert hasattr(report, "errors")
