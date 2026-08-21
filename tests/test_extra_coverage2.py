"""Second extra coverage — libdeps / verifier / scanner / diff / orphans / cli."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pkgcheck.diff import _load_json_report, diff_reports, list_logs
from pkgcheck.libdeps import _is_library_path, _should_report, _soname_match, check_library_deps
from pkgcheck.orphans import _is_orphan_excluded, find_orphans
from pkgcheck.scanner import (
    _is_pseudo,
    _is_safe_rel,
    _is_section_header,
    _unescape_path,
    scan_package_files,
)
from pkgcheck.verifier import PathStatus, _is_elf_candidate, _lexists, _run_workers, check_path


class SonameMatchTest(unittest.TestCase):
    def test_exact(self) -> None:
        self.assertTrue(_soname_match("libfoo.so.1", "libfoo.so.1"))

    def test_unversioned_needed(self) -> None:
        self.assertTrue(_soname_match("libfoo.so", "libfoo.so.1"))

    def test_unversioned_available(self) -> None:
        self.assertTrue(_soname_match("libfoo.so.1", "libfoo.so"))

    def test_available_startswith(self) -> None:
        self.assertTrue(_soname_match("libfoo.so.1", "libfoo.so.1.2.3"))

    def test_needed_startswith(self) -> None:
        self.assertTrue(_soname_match("libfoo.so.1.2.3", "libfoo.so.1"))

    def test_major_match(self) -> None:
        self.assertTrue(_soname_match("libfoo.so.1", "libfoo.so.1.2"))
        self.assertTrue(_soname_match("libfoo.so.1.2", "libfoo.so.1"))

    def test_major_mismatch(self) -> None:
        self.assertFalse(_soname_match("libfoo.so.1", "libfoo.so.2"))

    def test_different_base(self) -> None:
        self.assertFalse(_soname_match("libfoo.so.1", "libbar.so.1"))

    def test_no_so(self) -> None:
        self.assertFalse(_soname_match("libfoo.a", "libbar.a"))


class ShouldReportTest(unittest.TestCase):
    def test_done_ge_total(self) -> None:
        self.assertTrue(_should_report(10, 10, 0))

    def test_interval(self) -> None:
        import time

        self.assertTrue(_should_report(5, 10, time.monotonic() - 1))
        self.assertFalse(_should_report(5, 10, time.monotonic()))


class IsLibraryPathTest(unittest.TestCase):
    def test_lib64_so(self) -> None:
        self.assertTrue(_is_library_path("lib/libfoo.so"))
        self.assertTrue(_is_library_path("usr/lib64/libbar.so.1"))
        self.assertFalse(_is_library_path("usr/bin/tool"))

    def test_is_elf_candidate(self) -> None:
        self.assertTrue(_is_elf_candidate(0o755, "/usr/bin/foo"))
        self.assertTrue(_is_elf_candidate(0o644, "libfoo.so"))
        self.assertTrue(_is_elf_candidate(0o644, "libfoo.so.1"))
        self.assertFalse(_is_elf_candidate(0o644, "/etc/passwd"))


class VerifierExtraTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _p(self, rel: str) -> str:
        return str(self.dir / rel)

    def test_lexists_permission(self) -> None:
        with mock.patch("os.lstat", side_effect=PermissionError):
            with self.assertRaises(PermissionError):
                _lexists(self._p("x"))

    def test_check_path_permission_on_new_variant(self) -> None:
        # lstat fails with PermissionError for base path
        with mock.patch("os.lstat", side_effect=PermissionError):
            self.assertEqual(check_path(self._p("a"), new_suffix=".new"), PathStatus.NO_ACCESS)

    def test_check_path_backup_permission(self) -> None:
        with mock.patch("os.lstat", side_effect=FileNotFoundError):
            with mock.patch("pkgcheck.verifier._lexists", side_effect=PermissionError):
                self.assertEqual(check_path(self._p("a")), PathStatus.NO_ACCESS)

    def test_run_workers_sync_fallback(self) -> None:
        # Force ThreadPoolExecutor to fail
        with mock.patch("pkgcheck.verifier.ThreadPoolExecutor", side_effect=OSError("boom")):
            result = _run_workers(
                ["a", "b"], workers=2, worker=lambda x: x.upper(), on_progress=None
            )
            self.assertEqual(result, ["A", "B"])

    def test_run_workers_exception_in_worker(self) -> None:
        def boom(_):
            raise RuntimeError("boom")

        result = _run_workers(["a"], workers=2, worker=boom, on_progress=None)
        self.assertEqual(result, [None])


class ScannerExtraTest(unittest.TestCase):
    def test_is_pseudo_setup(self) -> None:
        self.assertFalse(_is_pseudo("var/log/setup/foo", ("var/log/",)))
        self.assertTrue(_is_pseudo("var/log/foo", ("var/log/",)))

    def test_is_safe_rel_edge(self) -> None:
        self.assertFalse(_is_safe_rel(""))
        self.assertFalse(_is_safe_rel("/a"))
        self.assertFalse(_is_safe_rel("a//b"))
        self.assertFalse(_is_safe_rel("a/./b"))
        self.assertFalse(_is_safe_rel("a/../b"))
        self.assertTrue(_is_safe_rel("a/b"))

    def test_unescape_no_backslash(self) -> None:
        self.assertEqual(_unescape_path("abc"), "abc")

    def test_unescape_clamp(self) -> None:
        # \777 = 511 -> clamp to 0xFF
        self.assertIn("\ufffd", _unescape_path("\\777"))

    def test_is_section_header_true(self) -> None:
        # REQUIRES: followed by non-path non-header -> true
        rels = ["REQUIRES:", "glibc"]
        self.assertTrue(_is_section_header(rels, 0))

    def test_is_section_header_false_due_to_path(self) -> None:
        rels = ["README:", "usr/bin/foo"]
        self.assertFalse(_is_section_header(rels, 0))

    def test_scan_python_fallback_ignores_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "subdir").mkdir()
            (d / "pkg-1").write_text("FILE LIST:\nusr/bin/foo\n")
            res = scan_package_files(d, None)
            self.assertIn(("pkg-1", "usr/bin/foo"), res.entries)

    def test_scan_rg_not_found_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "pkg-1").write_text("FILE LIST:\nusr/bin/foo\n")
            res = scan_package_files(d, None)
            self.assertTrue(len(res.entries) >= 1)


class DiffExtraTest(unittest.TestCase):
    def test_list_logs_no_dir(self) -> None:
        self.assertEqual(list_logs(Path("/nonexistent_xyz_123")), [])

    def test_list_logs_stat_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            p = d / "pkgcheck-01-01-2026-00-00-00.log"
            p.write_text("x")
            with mock.patch("pathlib.Path.stat", side_effect=OSError("boom")):
                self.assertEqual(list_logs(d), [])

    def test_load_json_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "a.json"
            p.write_text("not json")
            with self.assertRaises(RuntimeError):
                _load_json_report(p)

    def test_diff_broken_libs_no_diff(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            a = Path(tmp) / "a.json"
            b = Path(tmp) / "b.json"
            data = {"broken_libs": {"pkg": [{"binary": "/bin/x", "missing": ["lib.so"]}]}}
            import json

            a.write_text(json.dumps(data))
            b.write_text(json.dumps(data))
            diff = diff_reports(a, b)
            self.assertNotIn("broken_libs", diff["diff"])

    def test_diff_summary_delta(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            a = Path(tmp) / "a.json"
            b = Path(tmp) / "b.json"
            import json

            a.write_text(json.dumps({"summary": {"missing": 1}}))
            b.write_text(json.dumps({"summary": {"missing": 2}}))
            diff = diff_reports(a, b)
            self.assertEqual(diff["diff"]["summary"]["missing"]["delta"], 1)


class OrphansExtraTest(unittest.TestCase):
    def test_is_orphan_excluded_package(self) -> None:
        self.assertTrue(_is_orphan_excluded("var/log/packages/foo"))

    def test_is_orphan_excluded_package_exact(self) -> None:
        self.assertTrue(_is_orphan_excluded("var/log/packages"))

    def test_find_orphans_value_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "usr" / "bin").mkdir(parents=True)
            (root / "usr" / "bin" / "orphan").write_text("x")
            # Force relpath ValueError by mocking os.path.relpath
            with mock.patch("os.path.relpath", side_effect=ValueError("boom")):
                res = find_orphans(set(), root=root)
                # should not crash
                self.assertIsInstance(res, list)

    def test_find_orphans_prune(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "var" / "log").mkdir(parents=True)
            (root / "var" / "log" / "syslog").write_text("x")
            res = find_orphans(set(), root=root)
            self.assertEqual(res, [])

    def test_i18n_traditional(self) -> None:
        from pkgcheck.i18n import _is_traditional_zh, _validate

        self.assertTrue(_is_traditional_zh("zh_TW"))
        self.assertEqual(_validate("zh_TW"), "en")


class LibdepsExtraTest(unittest.TestCase):
    def test_get_needed_libs_timeout(self) -> None:
        from pkgcheck.libdeps import _get_needed_libs

        with mock.patch("pkgcheck.libdeps.subprocess.run", side_effect=OSError("boom")):
            self.assertEqual(_get_needed_libs("/x", "readelf"), [])

    def test_readelf_symbols_none(self) -> None:
        from pkgcheck.libdeps import _readelf_symbols

        with mock.patch("pkgcheck.libdeps.subprocess.run", side_effect=OSError("boom")):
            self.assertIsNone(_readelf_symbols("/x", "readelf"))

    def test_undefined_symbols_empty(self) -> None:
        from pkgcheck.libdeps import _undefined_symbols

        with mock.patch("pkgcheck.libdeps.subprocess.run", side_effect=OSError("boom")):
            self.assertEqual(_undefined_symbols("/x", set(), "readelf"), [])

    def test_check_library_deps_with_progress(self) -> None:
        events = []
        res = check_library_deps(
            [], workers=2, readelf_bin="readelf", owner_index={}, on_progress=events.append
        )
        self.assertEqual(res, [])

    def test_is_library_path_false(self) -> None:
        self.assertFalse(_is_library_path("usr/share/doc/foo.so"))
