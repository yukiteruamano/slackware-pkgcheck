"""Test suite for pkgcheck (stdlib unittest, no external dependencies)."""

from __future__ import annotations

import io
import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

from pkgcheck import i18n
from pkgcheck.cli import _backup_suffixes, _new_suffix, _pseudo_prefixes
from pkgcheck.reporter import Summary, _text_report, json_report, print_breakdown, report_path
from pkgcheck.scanner import scan_package_files
from pkgcheck.verifier import PathStatus, check_path, verify_paths


def _summary() -> Summary:
    return Summary(
        packages=2,
        files_checked=5,
        missing=1,
        backup=0,
        pending_new=0,
        no_access=0,
        errors=1,
        excluded_install=3,
        excluded_pseudo=4,
    )


class I18nTest(unittest.TestCase):
    def _reset(self) -> None:
        i18n.set_language("en")

    def tearDown(self) -> None:
        self._reset()

    def _detect(self, lang: str | None = None, env: dict[str, str] | None = None) -> str:
        env = env or {}
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch("pkgcheck.i18n.locale.getlocale", return_value=(None, None)),
        ):
            return i18n.detect_language(lang)

    def test_override_wins(self) -> None:
        self.assertEqual(self._detect("ja", env={"LANG": "es_ES.UTF-8"}), "ja")

    def test_env_var(self) -> None:
        self.assertEqual(self._detect(env={"PKGCHECK_LANG": "pt"}), "pt")

    def test_os_language(self) -> None:
        self.assertEqual(self._detect(env={"LANG": "fr_FR.UTF-8"}), "fr")
        self.assertEqual(self._detect(env={"LANG": "zh_CN"}), "zh")

    def test_os_normalizes_full_locale(self) -> None:
        self.assertEqual(self._detect(env={"LANG": "es_ES.UTF-8"}), "es")

    def test_traditional_chinese_falls_back_to_english(self) -> None:
        self.assertEqual(self._detect(env={"LANG": "zh_TW"}), "en")
        self.assertEqual(self._detect(env={"LANG": "zh_Hant_TW"}), "en")
        self.assertEqual(self._detect("zh_TW"), "en")

    def test_unsupported_falls_back_to_english(self) -> None:
        self.assertEqual(self._detect(env={"LANG": "C"}), "en")
        self.assertEqual(self._detect("xx"), "en")

    def test_is_supported(self) -> None:
        self.assertTrue(i18n.is_supported("es_ES"))
        self.assertTrue(i18n.is_supported("zh"))
        self.assertTrue(i18n.is_supported("zh_Hans_CN"))
        self.assertTrue(i18n.is_supported("en_US"))
        self.assertFalse(i18n.is_supported("xx"))
        self.assertFalse(i18n.is_supported("zh_TW"))

    def test_simplified_chinese_variants_map_to_zh(self) -> None:
        self.assertEqual(self._detect("zh_Hans_CN"), "zh")
        self.assertEqual(self._detect(env={"LANG": "zh_CN.GB18030"}), "zh")

    def test_t_identity_when_untranslated(self) -> None:
        i18n.set_language("es")
        self.assertEqual(i18n.t("Something new"), "Something new")

    def test_t_spanish(self) -> None:
        i18n.set_language("es")
        self.assertIn("Escaneando", i18n.t("Scanning package records in {path}..."))

    def test_t_preserves_placeholders(self) -> None:
        i18n.set_language("ja")
        msg = i18n.t("[green]Log saved to:[/green] {path}").format(path="/x")
        self.assertEqual(msg, "[green]ログを保存しました:[/green] /x")


class VerifierTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.base = str(self.dir)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _path(self, rel: str) -> str:
        return os.path.join(self.base, rel)

    def test_exists(self) -> None:
        open(self._path("a.conf"), "w").close()
        self.assertIs(check_path(self._path("a.conf")), PathStatus.EXISTS)

    def test_missing(self) -> None:
        self.assertIs(check_path(self._path("a.conf")), PathStatus.MISSING)

    def test_backup(self) -> None:
        open(self._path("a.conf.bak"), "w").close()
        self.assertIs(check_path(self._path("a.conf")), PathStatus.BACKUP)

    def test_new_variant_for_plain(self) -> None:
        open(self._path("b.conf.new"), "w").close()
        self.assertIs(check_path(self._path("b.conf")), PathStatus.NEW_PENDING)

    def test_new_registered_renamed(self) -> None:
        open(self._path("c.conf"), "w").close()
        self.assertIs(check_path(self._path("c.conf.new")), PathStatus.EXISTS)

    def test_new_registered_pending(self) -> None:
        open(self._path("d.conf.new"), "w").close()
        self.assertIs(check_path(self._path("d.conf.new")), PathStatus.NEW_PENDING)

    def test_new_registered_missing(self) -> None:
        self.assertIs(check_path(self._path("e.conf.new")), PathStatus.MISSING)

    def test_broken_symlink_counts_as_present(self) -> None:
        os.symlink(self._path("nonexistent"), self._path("f.conf"))
        self.assertIs(check_path(self._path("f.conf")), PathStatus.EXISTS)

    def test_empty_new_suffix_uses_default(self) -> None:
        open(self._path("g.conf"), "w").close()
        self.assertIs(check_path(self._path("g.conf"), new_suffix=""), PathStatus.EXISTS)

    def test_verify_paths_preserves_order_and_progress(self) -> None:
        for name in ("a", "b", "c"):
            open(self._path(name), "w").close()
        paths = [self._path("a"), self._path("nope"), self._path("c")]
        events: list[int] = []
        statuses = verify_paths(paths, 4, on_progress=events.append)
        self.assertEqual(statuses, [PathStatus.EXISTS, PathStatus.MISSING, PathStatus.EXISTS])
        self.assertEqual(events, [3])

    def test_verify_paths_empty(self) -> None:
        self.assertEqual(verify_paths([], 4), [])


class ScannerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.rg = shutil.which("rg")
        if self.rg is None:
            self.skipTest("ripgrep not available")
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write(self, name: str, content: bytes) -> None:
        (self.dir / name).write_bytes(content)

    def _scan(self):
        return scan_package_files(self.dir, self.rg)

    def test_entries_and_exclusions(self) -> None:
        self._write(
            "demo-1.0",
            b"PACKAGE NAME:     demo-1.0\nFILE LIST:\nusr/bin/foo\netc/conf\n"
            b"install/doinst.sh\ndev/null\nusr/share/doc/demo/README\n",
        )
        result = self._scan()
        expected = {
            ("demo-1.0", "usr/bin/foo"),
            ("demo-1.0", "etc/conf"),
            ("demo-1.0", "usr/share/doc/demo/README"),
        }
        self.assertEqual(set(result.entries), expected)
        self.assertEqual(result.excluded_install, 1)
        self.assertEqual(result.excluded_pseudo, 1)

    def test_octal_unescape(self) -> None:
        self._write(
            "demo-2.0",
            b"FILE LIST:\nusr/bin/x\netc/\\303\\263n.conf\n",
        )
        result = self._scan()
        self.assertIn(("demo-2.0", "etc/ón.conf"), result.entries)

    def test_last_line_without_newline(self) -> None:
        self._write("demo-3.0", b"FILE LIST:\nusr/bin/a\nusr/bin/b")
        result = self._scan()
        self.assertIn(("demo-3.0", "usr/bin/b"), result.entries)

    def test_requires_section_stops_extraction(self) -> None:
        self._write(
            "meta-1.0",
            b"FILE LIST:\nusr/bin/bar\nREQUIRES:\nglibc\nxz\n",
        )
        result = self._scan()
        self.assertEqual(result.entries, [("meta-1.0", "usr/bin/bar")])

    def test_all_caps_file_is_not_a_header(self) -> None:
        self._write(
            "caps-1.0",
            b"FILE LIST:\nREADME:\nusr/share/doc/x\n",
        )
        result = self._scan()
        self.assertIn(("caps-1.0", "README:"), result.entries)
        self.assertIn(("caps-1.0", "usr/share/doc/x"), result.entries)

    def test_all_caps_file_before_real_header_is_kept(self) -> None:
        self._write(
            "caps2-1.0",
            b"FILE LIST:\nusr/bin/foo\nREADME:\nREQUIRES:\nglibc\n",
        )
        result = self._scan()
        self.assertEqual(
            result.entries,
            [("caps2-1.0", "usr/bin/foo"), ("caps2-1.0", "README:")],
        )

    def test_all_caps_file_at_end_of_file_is_kept(self) -> None:
        self._write(
            "caps3-1.0",
            b"FILE LIST:\nusr/bin/foo\nREADME:",
        )
        result = self._scan()
        self.assertEqual(
            result.entries,
            [("caps3-1.0", "usr/bin/foo"), ("caps3-1.0", "README:")],
        )

    def test_multiple_file_list_markers(self) -> None:
        self._write(
            "multi-1.0",
            b"FILE LIST:\nusr/bin/a\nFILE LIST:\nusr/bin/b\n",
        )
        result = self._scan()
        self.assertIn(("multi-1.0", "usr/bin/a"), result.entries)
        self.assertIn(("multi-1.0", "usr/bin/b"), result.entries)


class ReporterTest(unittest.TestCase):
    def tearDown(self) -> None:
        i18n.set_language("en")

    def _indexes(self):
        return (
            {"pkg": ["/a"]},  # missing
            {"pkg": ["/b"]},  # no_access
            {"pkg": ["/c"]},  # backup
            {"pkg": ["/d"]},  # pending_new
            {"pkg": ["/e"]},  # errors
        )

    def test_report_path(self) -> None:
        when = datetime(2026, 8, 7, 12, 34, 56)
        self.assertEqual(
            report_path(Path("/var/log/pkgcheck"), when, "log"),
            Path("/var/log/pkgcheck/pkgcheck-07-08-2026-12-34-56.log"),
        )
        self.assertEqual(
            report_path(Path("/var/log/pkgcheck"), when, "json"),
            Path("/var/log/pkgcheck/pkgcheck-07-08-2026-12-34-56.json"),
        )

    def test_json_report_keys(self) -> None:
        doc = json.loads(json_report(_summary(), *self._indexes()))
        self.assertEqual(doc["generator"], "pkgcheck")
        self.assertEqual(doc["summary"]["errors"], 1)
        self.assertEqual(doc["files_errors"], {"pkg": ["/e"]})
        self.assertEqual(doc["missing"], {"pkg": ["/a"]})

    def test_json_report_timestamp(self) -> None:
        when = datetime(2026, 8, 7, 12, 34, 56)
        doc = json.loads(json_report(_summary(), *self._indexes(), when))
        self.assertEqual(doc["timestamp"], "2026-08-07T12:34:56")

    def test_text_report_localized(self) -> None:
        i18n.set_language("es")
        text = _text_report(_summary(), *self._indexes(), datetime(2026, 8, 7, 12, 34, 56))
        self.assertIn("Paquetes analizados", text)
        self.assertIn("FALTANTES:", text)
        self.assertIn("ERRORES:", text)
        self.assertIn("Archivos faltantes: 1", text)

    def test_print_breakdown_max_rows_zero(self) -> None:
        buf = io.StringIO()
        from rich.console import Console

        console = Console(file=buf, width=100, force_terminal=False)
        data = {"a": ["/x"], "b": ["/y"]}
        print_breakdown(console, data, max_rows=0)
        print_breakdown(console, data, max_rows=-1)
        self.assertEqual(buf.getvalue().strip(), "")


class CliHelperTest(unittest.TestCase):
    def test_backup_suffixes(self) -> None:
        ns = mock.Mock(backup_suffixes=" .bak, .orig ,")
        self.assertEqual(_backup_suffixes(ns), (".bak", ".orig"))

    def test_new_suffix(self) -> None:
        ns = mock.Mock(new_suffix=" .new ")
        self.assertEqual(_new_suffix(ns), ".new")

    def test_pseudo_prefixes(self) -> None:
        ns = mock.Mock(exclude=["/mnt, media/", "srv"])
        prefixes = _pseudo_prefixes(ns)
        self.assertIn("mnt/", prefixes)
        self.assertIn("media/", prefixes)
        self.assertIn("srv/", prefixes)
        self.assertNotIn("/mnt/", prefixes)


class CliIntegrationTest(unittest.TestCase):
    def _run(self, *args: str):
        import subprocess
        import sys

        return subprocess.run(
            [sys.executable, "-m", "pkgcheck", *args],
            capture_output=True,
            text=True,
        )

    def test_lang_full_locale_help(self) -> None:
        result = self._run("--lang", "es_ES", "--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Directorio con los registros", result.stdout)

    def test_unsupported_lang_errors(self) -> None:
        result = self._run("--lang", "xx")
        self.assertEqual(result.returncode, 2)
        self.assertIn("xx", result.stderr)


if __name__ == "__main__":
    unittest.main()
