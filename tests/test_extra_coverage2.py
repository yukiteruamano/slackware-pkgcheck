"""Second extra coverage — libdeps / verifier / scanner / diff / orphans / cli."""

from __future__ import annotations

import os
import sys
import tempfile
import types
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
        try:
            from helpers import _get_needed_libs
        except ModuleNotFoundError:
            from tests.helpers import _get_needed_libs

        with mock.patch("pkgcheck.libdeps.subprocess.run", side_effect=OSError("boom")):
            self.assertEqual(_get_needed_libs("/x", "ldd"), [])

    def test_nm_symbols_none(self) -> None:
        try:
            from helpers import _ldd_symbols
        except ModuleNotFoundError:
            from tests.helpers import _ldd_symbols

        with mock.patch("pkgcheck.libdeps.subprocess.run", side_effect=OSError("boom")):
            self.assertIsNone(_ldd_symbols("/x", "nm"))

    def test_undefined_symbols_empty(self) -> None:
        try:
            from helpers import _undefined_symbols
        except ModuleNotFoundError:
            from tests.helpers import _undefined_symbols

        with mock.patch("pkgcheck.libdeps.subprocess.run", side_effect=OSError("boom")):
            self.assertEqual(_undefined_symbols("/x", set(), "nm"), [])

    def test_check_library_deps_with_progress(self) -> None:
        events = []
        res = check_library_deps(
            [], workers=2, ldd_bin="ldd", owner_index={}, on_progress=events.append
        )
        self.assertEqual(res, [])

    def test_is_library_path_false(self) -> None:
        self.assertFalse(_is_library_path("usr/share/doc/foo.so"))


class LibdepsGapsTest(unittest.TestCase):
    def test_canonical_hyphen(self) -> None:
        from pkgcheck.libdeps import _canonical_libname

        self.assertEqual(_canonical_libname("libfoo-1.so"), "libfoo.so.1")
        self.assertEqual(_canonical_libname("libfoo-bar.so"), "libfoo-bar.so")
        self.assertEqual(_canonical_libname("libfoo.so.1"), "libfoo.so.1")

    def test_build_env_extra_and_hijack_cleared(self) -> None:
        from pkgcheck.libdeps import _build_ldd_env, _build_nm_env

        poison = {
            "LD_LIBRARY_PATH": "x",
            "LD_PRELOAD": "y",
            "LD_AUDIT": "z",
            "LD_BIND_NOW": "1",
        }
        with mock.patch.dict(os.environ, poison, clear=False):
            env = _build_ldd_env({"PKGCHECK_TEST": "1"})
            self.assertEqual(env["PKGCHECK_TEST"], "1")
            self.assertEqual(env["LC_ALL"], "C")
            for key in poison:
                self.assertNotIn(key, env)
        env2 = _build_nm_env({"PKGCHECK_TEST": "2"})
        self.assertEqual(env2["PKGCHECK_TEST"], "2")
        self.assertEqual(env2["LC_ALL"], "C")

    def test_ldd_static_stderr_dedup(self) -> None:
        from pkgcheck.libdeps import _ldd_missing

        static = types.SimpleNamespace(stdout="not a dynamic executable", stderr="")
        with mock.patch("pkgcheck.libdeps.subprocess.run", return_value=static):
            self.assertEqual(_ldd_missing("/x", "ldd"), [])
        err = types.SimpleNamespace(stdout="linux-vdso.so.1", stderr="\tlibfoo.so.1 => not found\n")
        with mock.patch("pkgcheck.libdeps.subprocess.run", return_value=err):
            self.assertEqual(_ldd_missing("/x", "ldd"), ["libfoo.so.1"])
        dup = types.SimpleNamespace(
            stdout="\tlibfoo.so.1 => not found\n\tlibfoo.so.1 => not found\n", stderr=""
        )
        with mock.patch("pkgcheck.libdeps.subprocess.run", return_value=dup):
            self.assertEqual(_ldd_missing("/x", "ldd"), ["libfoo.so.1"])

    def test_ldd_stdout_stderr_cross_dup(self) -> None:
        from pkgcheck.libdeps import _ldd_missing

        both = types.SimpleNamespace(
            stdout="\tlibfoo.so.1 => not found\n",
            stderr="\tlibfoo.so.1 => not found\n\tlibbar.so.2 => not found\n",
        )
        with mock.patch("pkgcheck.libdeps.subprocess.run", return_value=both):
            self.assertEqual(_ldd_missing("/x", "ldd"), ["libfoo.so.1", "libbar.so.2"])

    def test_filter_stub_exact_soname(self) -> None:
        from pkgcheck.libdeps import _filter_missing_with_owner

        self.assertEqual(_filter_missing_with_owner([], {}), [])
        self.assertEqual(
            _filter_missing_with_owner(["libpthread.so.0"], {"libc.so.6": "glibc"}), []
        )
        self.assertEqual(_filter_missing_with_owner(["libfoo.so"], {"libfoo.so": "pkg"}), [])
        self.assertEqual(_filter_missing_with_owner(["libfoo.so.1"], {"libfoo.so.1.2": "pkg"}), [])
        self.assertEqual(_filter_missing_with_owner(["libnope.so"], {}), ["libnope.so"])

    def test_owner_index_hyphen_and_find(self) -> None:
        from pkgcheck.libdeps import build_library_owner_index, find_missing_owner

        index = build_library_owner_index([("pkg", "usr/lib64/libfoo-1.so")])
        self.assertEqual(index.get("libfoo.so.1"), "pkg")
        self.assertEqual(find_missing_owner(["libfoo.so.1"], index), {"libfoo.so.1": "pkg"})
        index2 = build_library_owner_index([("pkg", "usr/lib/libbar.so.1.2")])
        self.assertEqual(find_missing_owner(["libbar.so.1"], index2), {"libbar.so.1": "pkg"})
        self.assertEqual(find_missing_owner(["libnope.so"], index2), {"libnope.so": None})

    def test_nm_parse_defined(self) -> None:
        from pkgcheck.libdeps import _nm_symbols

        out = (
            "0000000000000000 T main\n"
            "0000000000000000 T helper@GLIBC_2.2.5\n"
            "                 U puts\n"
        )
        good = types.SimpleNamespace(stdout=out, stderr="", returncode=0)
        with mock.patch("pkgcheck.libdeps.subprocess.run", return_value=good):
            self.assertEqual(_nm_symbols("/x", "nm"), {"main", "helper@GLIBC_2.2.5"})
        two = types.SimpleNamespace(stdout="T lone\nU other\n", stderr="", returncode=0)
        with mock.patch("pkgcheck.libdeps.subprocess.run", return_value=two):
            self.assertEqual(_nm_symbols("/x", "nm"), {"lone"})
        empty = types.SimpleNamespace(stdout="", stderr="", returncode=1)
        with mock.patch("pkgcheck.libdeps.subprocess.run", return_value=empty):
            self.assertIsNone(_nm_symbols("/x", "nm"))

    def test_undef_parse_and_filter(self) -> None:
        from pkgcheck.libdeps import _get_undefined_symbols

        out = "                 U puts\n                 U printf@GLIBC_2.2.5\n                 U puts\n"
        good = types.SimpleNamespace(stdout=out, stderr="", returncode=0)
        with mock.patch("pkgcheck.libdeps.subprocess.run", return_value=good):
            self.assertEqual(_get_undefined_symbols("/x", {"puts"}, "nm"), ["printf@GLIBC_2.2.5"])
        blank = types.SimpleNamespace(stdout="\n   \n", stderr="", returncode=0)
        with mock.patch("pkgcheck.libdeps.subprocess.run", return_value=blank):
            self.assertEqual(_get_undefined_symbols("/x", set(), "nm"), [])

    def test_collect_and_check_symbols(self) -> None:
        from pkgcheck.libdeps import (
            check_undefined_symbols,
            collect_defined_symbols,
        )

        with mock.patch("pkgcheck.libdeps._nm_symbols", side_effect=[{"a"}, {"b"}]):
            self.assertEqual(collect_defined_symbols(["/x", "/y"], 2, "nm"), {"a", "b"})
        with mock.patch("pkgcheck.libdeps._get_undefined_symbols", side_effect=[["u1"], []]):
            events: list[int] = []
            res = check_undefined_symbols(["/x", "/y"], set(), 2, "nm", on_progress=events.append)
        self.assertEqual(res, [["u1"], []])
        self.assertEqual(events[-1], 2)


class VerifierGapsTest(unittest.TestCase):
    def test_sync_fallback(self) -> None:
        from pkgcheck.verifier import _run_workers

        with mock.patch("pkgcheck.verifier.ThreadPoolExecutor", side_effect=OSError("x")):
            events: list[int] = []
            self.assertEqual(_run_workers(["a", "b"], 2, str.upper, events.append), ["A", "B"])
            self.assertEqual(events, [1, 2])
            self.assertEqual(_run_workers(["a"], 1, lambda _p: 1 / 0, None), [None])

    def test_backup_no_access(self) -> None:
        from pkgcheck.verifier import PathStatus, check_path

        with mock.patch("pkgcheck.verifier._lexists", side_effect=[False, PermissionError()]):
            self.assertIs(check_path("/nope/missing"), PathStatus.NO_ACCESS)

    def test_elf_errors(self) -> None:
        from pkgcheck.verifier import _is_elf

        with tempfile.TemporaryDirectory() as tmp:
            adir = Path(tmp) / "adir"
            adir.mkdir()
            with mock.patch("os.close", side_effect=OSError("busy")):
                self.assertFalse(_is_elf(str(adir)))
            notes = Path(tmp) / "notes.txt"
            notes.write_text("hello")
            notes.chmod(0o644)
            with mock.patch("os.close", side_effect=OSError("busy")):
                self.assertFalse(_is_elf(str(notes)))
            exe = Path(tmp) / "prog"
            exe.write_bytes(b"\x7fELF....")
            exe.chmod(0o755)
            with mock.patch("os.fdopen", side_effect=OSError("boom")):
                with mock.patch("os.close", side_effect=OSError("busy")):
                    self.assertFalse(_is_elf(str(exe)))
        with mock.patch("os.open", return_value=99):
            with mock.patch("os.fstat", side_effect=OSError("boom")):
                with mock.patch("os.close", side_effect=OSError("busy")):
                    self.assertFalse(_is_elf("/x"))

    def test_with_elf_error_pair(self) -> None:
        from pkgcheck.verifier import PathStatus, verify_paths_with_elf

        with mock.patch("pkgcheck.verifier.check_path_and_elf", side_effect=RuntimeError("boom")):
            statuses, flags = verify_paths_with_elf(["/x"], 1)
        self.assertEqual(statuses, [PathStatus.ERROR])
        self.assertEqual(flags, [False])


class ScannerGapsTest(unittest.TestCase):
    def test_safe_rel_rejects(self) -> None:
        from pkgcheck.scanner import _is_pseudo, _is_safe_rel

        self.assertFalse(_is_safe_rel("x" * 5000))
        self.assertFalse(_is_safe_rel("a\x00b"))
        self.assertFalse(_is_safe_rel("a\x01b"))
        self.assertFalse(_is_pseudo("var/log/pkgcheck/a.log", ("var/log/",)))
        self.assertFalse(_is_pseudo("var/log/setup/a.log", ("var/log/",)))

    def test_python_scan_oserror(self) -> None:
        from pkgcheck.scanner import _python_scan

        with mock.patch.object(Path, "iterdir", side_effect=OSError("boom")):
            with self.assertRaises(RuntimeError):
                _python_scan(Path("/tmp"))

    def test_python_scan_unreadable_skipped(self) -> None:
        from pkgcheck.scanner import _python_scan

        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "demo-1.0").write_text("FILE LIST:\nusr/bin/foo\n")
            with mock.patch.object(Path, "read_text", side_effect=OSError("boom")):
                self.assertEqual(_python_scan(Path(tmp)), {})

    def test_scan_preamble_and_no_marker(self) -> None:
        from pkgcheck.scanner import scan_package_files

        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "a-1.0").write_text("NAME: a\nFILE LIST:\nusr/bin/a\n")
            (Path(tmp) / "b-1.0").write_text("NAME: b, no file list here\n")
            res = scan_package_files(Path(tmp), None)
        self.assertEqual(res.entries, [("a-1.0", "usr/bin/a")])

    def test_scan_rg_branches(self) -> None:
        import subprocess

        from pkgcheck.scanner import scan_package_files

        with tempfile.TemporaryDirectory() as tmp:
            ok = types.SimpleNamespace(stdout="pkg:FILE LIST:\n\n", stderr="", returncode=0)
            with mock.patch("pkgcheck.scanner.subprocess.run", return_value=ok):
                res = scan_package_files(Path(tmp), "rg", subprocess_env={"X": "1"})
            self.assertEqual(res.entries, [])
            skip = types.SimpleNamespace(
                stdout="pkg:FILE LIST:\n"
                "pkg:\n"
                "pkg:somedir/\n"
                "pkg:../escape\n"
                "pkg:\\056\\056\\057etc\n"
                "pkg:usr/bin/ok\n",
                stderr="",
                returncode=0,
            )
            with mock.patch("pkgcheck.scanner.subprocess.run", return_value=skip):
                res = scan_package_files(Path(tmp), "rg")
            self.assertEqual(res.entries, [("pkg", "usr/bin/ok")])
            self.assertEqual(res.excluded_pseudo, 2)
            with mock.patch(
                "pkgcheck.scanner.subprocess.run",
                side_effect=subprocess.TimeoutExpired("rg", 300),
            ):
                with self.assertRaises(RuntimeError):
                    scan_package_files(Path(tmp), "rg")
            with mock.patch("pkgcheck.scanner.subprocess.run", side_effect=OSError("x")):
                with self.assertRaises(RuntimeError):
                    scan_package_files(Path(tmp), "rg")
            bad = types.SimpleNamespace(stdout="", stderr="nope", returncode=2)
            with mock.patch("pkgcheck.scanner.subprocess.run", return_value=bad):
                with self.assertRaises(RuntimeError):
                    scan_package_files(Path(tmp), "rg")


class CliGapsTest(unittest.TestCase):
    def test_resolve_latest(self) -> None:
        from pkgcheck.cli import _resolve_log_path

        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp)
            ordered = []
            for i, name in enumerate(["pkgcheck-a.log", "pkgcheck-b.json", "pkgcheck-c.json"]):
                p = log_dir / name
                p.write_text("{}")
                os.utime(p, (1000 + i * 10, 1000 + i * 10))
                ordered.append(p)
            self.assertEqual(_resolve_log_path("latest", log_dir), ordered[2])
            self.assertEqual(_resolve_log_path("latest-2", log_dir), ordered[1])
            self.assertIsNone(_resolve_log_path("latest-0", log_dir))
            self.assertIsNone(_resolve_log_path("latest-9", log_dir))
            self.assertEqual(_resolve_log_path("latest-x", log_dir), Path("latest-x"))
            self.assertIsNone(_resolve_log_path(None, log_dir))
            self.assertEqual(_resolve_log_path(str(ordered[0]), log_dir), ordered[0])

    def test_suffix_fallbacks(self) -> None:
        import argparse

        from pkgcheck.cli import _backup_suffixes, _new_suffix
        from pkgcheck.verifier import _DEFAULT_BACKUP_SUFFIXES, _DEFAULT_NEW_SUFFIX

        empty = argparse.Namespace(backup_suffixes=" , ", new_suffix="")
        self.assertEqual(_backup_suffixes(empty), ())
        self.assertEqual(_new_suffix(empty), _DEFAULT_NEW_SUFFIX)
        bad = argparse.Namespace(backup_suffixes=".\x01", new_suffix="")
        self.assertEqual(_backup_suffixes(bad), _DEFAULT_BACKUP_SUFFIXES)

    def test_main_workers_invalid(self) -> None:
        from pkgcheck import cli

        with tempfile.TemporaryDirectory() as tmp:
            argv = ["pkgcheck", "--packages-dir", tmp, "--workers", "0", "--no-elevate"]
            with mock.patch.object(sys, "argv", argv):
                with self.assertRaises(SystemExit):
                    cli.main()
            with mock.patch.object(sys, "argv", ["pkgcheck", "--lang", "xx"]):
                with self.assertRaises(SystemExit):
                    cli.main()

    def test_main_arg_validation_errors(self) -> None:
        from pkgcheck import cli

        with tempfile.TemporaryDirectory() as tmp:
            pkgfile = Path(tmp) / "demo-1.0"
            pkgfile.write_text("x")
            cases = [
                ["pkgcheck", "--packages-dir", tmp, "--max-rows", "0", "--no-elevate"],
                ["pkgcheck", "--packages-dir", tmp, "--exclude", "a\x01", "--no-elevate"],
                [
                    "pkgcheck",
                    "--packages-dir",
                    tmp,
                    "--orphans",
                    "--orphans-root",
                    "/nonexistent_xyz_123",
                    "--no-elevate",
                ],
                ["pkgcheck", "--packages-dir", str(pkgfile), "--no-elevate"],
                ["pkgcheck", "--packages-dir", tmp, "--max-rows", "3000", "--no-elevate"],
                ["pkgcheck", "--packages-dir", tmp, "--backup-suffixes", ".", "--no-elevate"],
                [
                    "pkgcheck",
                    "--packages-dir",
                    tmp,
                    "--orphans",
                    "--orphans-root",
                    str(pkgfile),
                    "--no-elevate",
                ],
            ]
            for argv in cases:
                with mock.patch.object(sys, "argv", argv):
                    with self.assertRaises(SystemExit):
                        cli.main()

    def test_main_rg_ldd_invalid_paths(self) -> None:
        from pkgcheck import cli

        def fake_which(name: str) -> str | None:
            if name in ("rg", "ldd"):
                return f"/nonexistent/{name}"
            return "/bin/true"

        with tempfile.TemporaryDirectory() as tmp:
            argv = ["pkgcheck", "--packages-dir", tmp, "--no-elevate", "--check-libs-deps"]
            with mock.patch.object(sys, "argv", argv):
                with mock.patch("pkgcheck.cli.shutil.which", side_effect=fake_which):
                    with self.assertRaises(SystemExit):
                        cli.main()

    def test_main_ldd_invalid_only(self) -> None:
        from pkgcheck import cli

        def fake_which(name: str) -> str | None:
            if name == "ldd":
                return "/nonexistent/ldd"
            return "/bin/true"

        with tempfile.TemporaryDirectory() as tmp:
            argv = ["pkgcheck", "--packages-dir", tmp, "--no-elevate", "--check-libs-deps"]
            with mock.patch.object(sys, "argv", argv):
                with mock.patch("pkgcheck.cli.shutil.which", side_effect=fake_which):
                    with self.assertRaises(SystemExit):
                        cli.main()

    def test_main_deps_only_valid_run(self) -> None:
        from pkgcheck import cli

        with tempfile.TemporaryDirectory() as tmp:
            argv = [
                "pkgcheck",
                "--packages-dir",
                tmp,
                "--no-elevate",
                "--check-libs-deps",
            ]
            with mock.patch.object(sys, "argv", argv):
                with mock.patch("pkgcheck.cli.shutil.which", return_value="/bin/true"):
                    cli.main()

    def test_main_valid_libs_empty_run(self) -> None:
        from pkgcheck import cli

        with tempfile.TemporaryDirectory() as tmp:
            argv = [
                "pkgcheck",
                "--packages-dir",
                tmp,
                "--no-elevate",
                "--check-libs-deps",
                "--check-libs-symbols",
                "--exclude",
                ",",
                "--exclude",
                "mnt/",
            ]
            with mock.patch.object(sys, "argv", argv):
                with mock.patch("pkgcheck.cli.shutil.which", return_value="/bin/true"):
                    cli.main()

    def test_resolve_latest_empty(self) -> None:
        from pkgcheck.cli import _resolve_log_path

        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(_resolve_log_path("latest", Path(tmp)))

    def test_ensure_utf8_both_streams(self) -> None:
        from pkgcheck.cli import _ensure_utf8_environment

        class FakeOut:
            def __init__(self) -> None:
                self.encoding = "latin-1"

            def reconfigure(self, **kwargs: object) -> None:
                self.encoding = str(kwargs.get("encoding", self.encoding))

        class FakeNoReconf:
            encoding = "latin-1"

        fake_out, fake_err = FakeOut(), FakeNoReconf()
        with mock.patch.object(sys, "stdout", fake_out):
            with mock.patch.object(sys, "stderr", fake_err):
                prev, env = _ensure_utf8_environment()
        self.assertEqual(prev, "latin-1")
        self.assertEqual(env["LC_ALL"], "en_US.UTF-8")
        self.assertEqual(fake_out.encoding, "utf-8")
        self.assertEqual(fake_err.encoding, "latin-1")

    def test_main_nm_missing(self) -> None:
        from pkgcheck import cli

        def fake_which(name: str) -> str | None:
            return None if name == "nm" else "/bin/true"

        def fake_bad_nm(name: str) -> str | None:
            if name == "nm":
                return "/nonexistent/nm"
            return "/bin/true"

        with tempfile.TemporaryDirectory() as tmp:
            argv = [
                "pkgcheck",
                "--packages-dir",
                tmp,
                "--no-elevate",
                "--check-libs-deps",
                "--check-libs-symbols",
            ]
            with mock.patch.object(sys, "argv", argv):
                with mock.patch("pkgcheck.cli.shutil.which", side_effect=fake_which):
                    with self.assertRaises(SystemExit):
                        cli.main()
            with mock.patch.object(sys, "argv", argv):
                with mock.patch("pkgcheck.cli.shutil.which", side_effect=fake_bad_nm):
                    with self.assertRaises(SystemExit):
                        cli.main()

    def test_main_nonroot_and_elevate(self) -> None:
        from pkgcheck import cli
        from pkgcheck.validate import ValidationError

        def fake_which(name: str) -> str | None:
            return None if name in ("ldd", "sudo") else "/bin/true"

        with tempfile.TemporaryDirectory() as tmp:
            argv = ["pkgcheck", "--packages-dir", tmp, "--no-elevate", "--check-libs-deps"]
            with mock.patch.object(sys, "argv", argv):
                with mock.patch("os.geteuid", return_value=1000):
                    with mock.patch("pkgcheck.cli.shutil.which", side_effect=fake_which):
                        with self.assertRaises(SystemExit):
                            cli.main()
            argv2 = ["pkgcheck", "--packages-dir", tmp, "--elevate"]
            with mock.patch.object(sys, "argv", argv2):
                with mock.patch("os.geteuid", return_value=1000):
                    with mock.patch("pkgcheck.cli.shutil.which", return_value=None):
                        with self.assertRaises(RuntimeError):
                            cli.main()
            with mock.patch.object(sys, "argv", argv2):
                with mock.patch("os.geteuid", return_value=1000):
                    with mock.patch("pkgcheck.cli.shutil.which", return_value="/nonexistent/sudo"):
                        with self.assertRaises(RuntimeError):
                            cli.main()
            with mock.patch.object(sys, "argv", argv2):
                with mock.patch("os.geteuid", return_value=1000):
                    with mock.patch("pkgcheck.cli.shutil.which", return_value="/usr/bin/sudo"):
                        with mock.patch(
                            "pkgcheck.cli.validate_safe_path",
                            side_effect=ValidationError("bad"),
                        ):
                            with self.assertRaises(RuntimeError):
                                cli.main()
            with mock.patch.object(sys, "argv", argv2):
                with mock.patch("os.geteuid", return_value=1000):
                    with mock.patch("pkgcheck.cli.shutil.which", return_value="/usr/bin/sudo"):
                        with mock.patch("os.execvp", side_effect=OSError("boom")):
                            with self.assertRaises(RuntimeError):
                                cli.main()

    def test_main_ldd_missing(self) -> None:
        from pkgcheck import cli

        def fake_which(name: str) -> str | None:
            return None if name == "ldd" else "/bin/true"

        with tempfile.TemporaryDirectory() as tmp:
            argv = ["pkgcheck", "--packages-dir", tmp, "--no-elevate", "--check-libs-deps"]
            with mock.patch.object(sys, "argv", argv):
                with mock.patch("pkgcheck.cli.shutil.which", side_effect=fake_which):
                    with self.assertRaises(SystemExit):
                        cli.main()

    def test_main_diff_reports(self) -> None:
        import json

        from pkgcheck import cli

        with tempfile.TemporaryDirectory() as tmp:
            a = Path(tmp) / "a.json"
            b = Path(tmp) / "b.json"
            a.write_text(json.dumps({"summary": {"missing": 1}, "missing": {"pkg": ["/x"]}}))
            b.write_text(json.dumps({"summary": {"missing": 2}, "missing": {"pkg": ["/y"]}}))
            argv = ["pkgcheck", "--diff", "--from", str(a), "--to", str(b), "--no-elevate"]
            with mock.patch.object(sys, "argv", argv):
                cli.main()
            c = Path(tmp) / "c.json"
            c.write_text(a.read_text())
            argv2 = ["pkgcheck", "--diff", "--from", str(a), "--to", str(c), "--no-elevate"]
            with mock.patch.object(sys, "argv", argv2):
                cli.main()
            d = Path(tmp) / "d.json"
            d.write_text(json.dumps({"summary": {"missing": 1}, "missing": {"pkg": []}}))
            argv3 = ["pkgcheck", "--diff", "--from", str(a), "--to", str(d), "--no-elevate"]
            with mock.patch.object(sys, "argv", argv3):
                cli.main()
            e = Path(tmp) / "e.json"
            e.write_text(json.dumps({"summary": {"missing": 9}, "missing": {"pkg": ["/x"]}}))
            argv4 = ["pkgcheck", "--diff", "--from", str(a), "--to", str(e), "--no-elevate"]
            with mock.patch.object(sys, "argv", argv4):
                cli.main()
            f = Path(tmp) / "f.json"
            f.write_text(
                json.dumps(
                    {
                        "missing": {"pkg": ["/x"]},
                        "broken_libs": {
                            "pkg": [{"binary": "/b", "missing": ["libz.so"], "provided_by": {}}]
                        },
                    }
                )
            )
            g = Path(tmp) / "g.json"
            g.write_text(json.dumps({"missing": {"pkg": ["/x"]}, "broken_libs": {}}))
            argv5 = ["pkgcheck", "--diff", "--from", str(f), "--to", str(g), "--no-elevate"]
            with mock.patch.object(sys, "argv", argv5):
                cli.main()
            argv6 = [
                "pkgcheck",
                "--diff",
                "--from",
                str(a),
                "--to",
                str(b),
                "--json",
                "--no-elevate",
            ]
            with mock.patch.object(sys, "argv", argv6):
                cli.main()

    def test_main_diff_errors(self) -> None:
        from pkgcheck import cli

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(sys, "argv", ["pkgcheck", "--diff", "--no-elevate"]):
                with self.assertRaises(SystemExit):
                    cli.main()
            argv = [
                "pkgcheck",
                "--diff",
                "--from",
                "/none-a",
                "--to",
                "/none-b",
                "--no-elevate",
            ]
            with mock.patch.object(sys, "argv", argv):
                with self.assertRaises(SystemExit):
                    cli.main()
            t1 = Path(tmp) / "t1.log"
            t2 = Path(tmp) / "t2.log"
            t1.write_text("text")
            t2.write_text("text")
            argv2 = [
                "pkgcheck",
                "--diff",
                "--from",
                str(t1),
                "--to",
                str(t2),
                "--no-elevate",
            ]
            with mock.patch.object(sys, "argv", argv2):
                with self.assertRaises(SystemExit):
                    cli.main()
            argv3 = [
                "pkgcheck",
                "--diff",
                "--from",
                str(t1),
                "--to",
                "/none-b",
                "--no-elevate",
            ]
            with mock.patch.object(sys, "argv", argv3):
                with self.assertRaises(SystemExit):
                    cli.main()

    def test_main_list_logs_empty(self) -> None:
        from pkgcheck import cli

        with mock.patch.object(sys, "argv", ["pkgcheck", "--list-logs"]):
            with mock.patch("pkgcheck.cli.list_logs", return_value=[]):
                cli.main()

    def test_run_old_singular_shim(self) -> None:
        import io

        from rich.console import Console

        from pkgcheck.cli import _build_parser, _run

        console = Console(file=io.StringIO(), width=80)
        status = Console(file=io.StringIO(), width=80, stderr=True)
        parser = _build_parser()
        with tempfile.TemporaryDirectory() as tmp:
            args = parser.parse_args(["--packages-dir", tmp, "--quiet"])
            del args.check_libs_deps
            del args.check_lib_deps
            _run(console, status, args, Path(tmp), None)

    def test_run_text_branches(self) -> None:
        import io

        from rich.console import Console

        from pkgcheck.cli import _build_parser, _run
        from pkgcheck.verifier import PathStatus

        console = Console(file=io.StringIO(), width=80)
        status = Console(file=io.StringIO(), width=80, stderr=True)
        parser = _build_parser()
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "demo-1.0").write_text(
                "FILE LIST:\nusr/bin/a\nusr/bin/b\nusr/bin/c\nusr/bin/d\n"
            )
            argv = [
                "--packages-dir",
                tmp,
                "--exclude",
                "a\x01",
                "--orphans",
                "--orphans-root",
                tmp,
                "--max-rows",
                "1",
            ]
            args = parser.parse_args(argv)
            statuses = [
                PathStatus.MISSING,
                PathStatus.BACKUP,
                PathStatus.NEW_PENDING,
                PathStatus.ERROR,
            ]
            (Path(tmp) / "junk.txt").write_text("untracked")
            with mock.patch("pkgcheck.cli.verify_paths", return_value=statuses):
                with mock.patch("pkgcheck.cli._write_auto_log", return_value=Path("/tmp/x.log")):
                    _run(console, status, args, Path(tmp), None)
            args_quiet = parser.parse_args(
                ["--packages-dir", tmp, "--quiet", "--orphans", "--orphans-root", tmp]
            )
            with mock.patch("pkgcheck.cli.verify_paths", return_value=statuses):
                with mock.patch("pkgcheck.cli._write_auto_log", return_value=None):
                    _run(console, status, args_quiet, Path(tmp), None)

    def test_run_undefined_symbols_branch(self) -> None:
        import io

        from rich.console import Console

        from pkgcheck.cli import _build_parser, _run
        from pkgcheck.verifier import PathStatus

        console = Console(file=io.StringIO(), width=80)
        status = Console(file=io.StringIO(), width=80, stderr=True)
        parser = _build_parser()
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "demo-1.0").write_text("FILE LIST:\nprog\nprog2\n")
            args = parser.parse_args(
                ["--packages-dir", tmp, "--check-libs-deps", "--check-libs-symbols"]
            )
            verified = ([PathStatus.EXISTS, PathStatus.EXISTS], [True, True])
            with mock.patch("pkgcheck.cli.verify_paths_with_elf", return_value=verified):
                with mock.patch(
                    "pkgcheck.cli.check_undefined_symbols", return_value=[[], ["undefsym"]]
                ):
                    with mock.patch("pkgcheck.cli._write_auto_log", return_value=None):
                        _run(console, status, args, Path(tmp), None, "/bin/true", "/bin/true")

    def test_run_json_branches(self) -> None:
        import io

        from rich.console import Console

        from pkgcheck.cli import _build_parser, _run
        from pkgcheck.verifier import PathStatus

        console = Console(file=io.StringIO(), width=80)
        status = Console(file=io.StringIO(), width=80, stderr=True)
        parser = _build_parser()
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "demo-1.0").write_text("FILE LIST:\nusr/bin/a\n")
            args = parser.parse_args(["--packages-dir", tmp, "--json", "--no-elevate"])
            with mock.patch("pkgcheck.cli.verify_paths", return_value=[PathStatus.NO_ACCESS]):
                with mock.patch("pkgcheck.cli._write_auto_log", return_value=Path("/tmp/x.json")):
                    with mock.patch("os.geteuid", return_value=0):
                        _run(console, status, args, Path(tmp), None)
            args_quiet = parser.parse_args(
                ["--packages-dir", tmp, "--json", "--quiet", "--no-elevate"]
            )
            with mock.patch("pkgcheck.cli.verify_paths", return_value=[PathStatus.NO_ACCESS]):
                with mock.patch("pkgcheck.cli._write_auto_log", return_value=None):
                    with mock.patch("os.geteuid", return_value=0):
                        _run(console, status, args_quiet, Path(tmp), None)


class DiffOrphansReporterGapsTest(unittest.TestCase):
    def test_list_logs_oserror(self) -> None:
        from pkgcheck.diff import list_logs

        with mock.patch.object(Path, "is_dir", side_effect=OSError("boom")):
            self.assertEqual(list_logs(Path("/tmp")), [])
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "pkgcheck-broken.log").symlink_to("/nonexistent_xyz_target")
            (d / "pkgcheck-broken.json").symlink_to("/nonexistent_xyz_target")
            self.assertEqual(list_logs(d), [])

    def test_diff_orphans_equal_and_added(self) -> None:
        import json

        from pkgcheck.diff import diff_reports

        with tempfile.TemporaryDirectory() as tmp:
            a = Path(tmp) / "a.json"
            b = Path(tmp) / "b.json"
            a.write_text(
                json.dumps(
                    {
                        "orphans": ["/x"],
                        "missing": {"p": ["/m1"]},
                        "summary": {"missing": 1},
                    }
                )
            )
            b.write_text(
                json.dumps(
                    {
                        "orphans": ["/y"],
                        "missing": {"p": ["/m1", "/m2"]},
                        "summary": {"missing": 2},
                    }
                )
            )
            d = diff_reports(a, b)
            self.assertEqual(d["diff"]["orphans"], {"added": ["/y"], "removed": ["/x"]})
            c = Path(tmp) / "c.json"
            c.write_text(
                json.dumps(
                    {"orphans": ["/x"], "missing": {"p": ["/m1"]}, "summary": {"missing": 1}}
                )
            )
            d2 = diff_reports(a, c)
            self.assertNotIn("orphans", d2["diff"])
            self.assertNotIn("summary", d2["diff"])

    def test_diff_null_indexes(self) -> None:
        import json

        from pkgcheck.diff import diff_reports

        with tempfile.TemporaryDirectory() as tmp:
            a = Path(tmp) / "a.json"
            b = Path(tmp) / "b.json"
            a.write_text(json.dumps({"missing": None, "summary": {"missing": 1}}))
            b.write_text(json.dumps({"missing": {"p": ["/m"]}, "summary": {"missing": "lots"}}))
            d = diff_reports(a, b)
            self.assertIn("missing", d["diff"])
            self.assertEqual(d["diff"]["summary"]["missing"]["delta"], None)
            c = Path(tmp) / "c.json"
            c.write_text(json.dumps({"missing": {"p": ["/m"]}, "summary": {}}))
            d2 = diff_reports(c, a)
            self.assertIn("missing", d2["diff"])
            e = Path(tmp) / "e.json"
            e.write_text(json.dumps({"missing": {"p": "/scalar"}, "summary": {}}))
            d3 = diff_reports(c, e)
            self.assertIn("missing", d3["diff"])

    def test_orphan_excludes_and_walk(self) -> None:
        from pkgcheck.orphans import _is_orphan_excluded, find_orphans

        self.assertTrue(_is_orphan_excluded("var/log/pkgcheck/x.log"))
        self.assertTrue(_is_orphan_excluded("var/log/setup/x.log"))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "var" / "log").mkdir(parents=True)
            (root / "var" / "log" / "syslog").write_text("x")
            owned = root / "owned.txt"
            owned.write_text("x")
            extra = root / "extra.txt"
            extra.write_text("x")
            res = find_orphans({"/owned.txt"}, root=root)
        self.assertEqual(res, [str(extra)])

    def test_orphan_relpath_error(self) -> None:
        from pkgcheck.orphans import find_orphans

        real_relpath = os.path.relpath
        calls = {"n": 0}

        def flaky(first: str, second: str) -> str:
            calls["n"] += 1
            if calls["n"] == 1:
                raise ValueError("drive")
            return real_relpath(first, second)

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch("os.path.relpath", side_effect=flaky):
                res = find_orphans(set(), root=Path(tmp))
        self.assertIsInstance(res, list)

    def test_unique_path_stat_error(self) -> None:
        from datetime import datetime

        from pkgcheck.reporter import unique_report_path

        with mock.patch.object(Path, "exists", side_effect=OSError("boom")):
            p = unique_report_path(Path("/tmp"), datetime(2026, 1, 1), "log")
        self.assertTrue(str(p).endswith(".log"))

    def test_breakdown_limits(self) -> None:
        import io

        from rich.console import Console

        from pkgcheck.reporter import BrokenBinary, print_breakdown, print_broken_libs

        console = Console(file=io.StringIO(), width=80)
        print_breakdown(console, {}, max_rows=0)
        print_breakdown(console, {"p1": ["/a"], "p2": ["/b"]}, max_rows=1)
        print_breakdown(console, {"p": ["/a", "/b"]}, max_rows=1)
        print_broken_libs(
            console,
            {"p": [BrokenBinary(binary="/b", missing=["l"], provided_by={})]},
            max_rows=1,
        )

    def test_write_report_oserror(self) -> None:
        from pkgcheck.reporter import Summary, write_report

        zeros = {
            "packages": 0,
            "files_checked": 0,
            "missing": 0,
            "backup": 0,
            "pending_new": 0,
            "no_access": 0,
            "errors": 0,
            "excluded_install": 0,
            "excluded_pseudo": 0,
        }
        summary = Summary(**zeros)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "r.log"
            with mock.patch("os.replace", side_effect=OSError("boom")):
                with self.assertRaises(OSError):
                    write_report(out, summary, {}, {}, {}, {}, {})

    def test_reports_with_extras(self) -> None:
        from pkgcheck.reporter import Summary, _text_report, json_report

        summary = Summary(
            packages=1,
            files_checked=1,
            missing=0,
            backup=0,
            pending_new=0,
            no_access=0,
            errors=0,
            excluded_install=0,
            excluded_pseudo=0,
            undefined_symbol_binaries=1,
            orphans=1,
        )
        doc = json_report(summary, {}, {}, {}, {}, {}, None, None, {"p": {"/b": ["s"]}}, ["/o"])
        self.assertIn("undefined_symbols", doc)
        self.assertIn("orphans", doc)
        text = _text_report(summary, {}, {}, {}, {}, {}, None, None, {"p": {"/b": ["s"]}}, ["/o"])
        self.assertIn("ORPHANS", text)
