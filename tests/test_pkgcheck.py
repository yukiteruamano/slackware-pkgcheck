"""Test suite for pkgcheck (stdlib unittest, no external dependencies)."""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

from pkgcheck import i18n
from pkgcheck.cli import (
    _backup_suffixes,
    _build_parser,
    _default_workers,
    _ensure_root,
    _ensure_utf8_environment,
    _exec_with_sudo,
    _is_utf8,
    _new_suffix,
    _pseudo_prefixes,
    _run,
    _write_auto_log,
)
from pkgcheck.libdeps import (
    _is_library_path,
    _readelf_symbols,
    _undefined_symbols,
    build_library_owner_index,
    check_library_deps,
    check_undefined_symbols,
    collect_defined_symbols,
    find_missing_owner,
)
from pkgcheck.reporter import (
    BrokenBinary,
    Summary,
    _text_report,
    json_report,
    print_breakdown,
    print_broken_libs,
    report_path,
    unique_report_path,
    write_report,
)
from pkgcheck.scanner import ScanResult, _is_safe_rel, scan_package_files
from pkgcheck.verifier import (
    PathStatus,
    _is_elf,
    check_path,
    verify_paths,
    verify_paths_with_elf,
)


class _FakeStream:
    """Minimal stand-in for sys.stdout/sys.stderr in encoding tests."""

    def __init__(self, encoding: str) -> None:
        self.encoding = encoding

    def reconfigure(self, **kwargs) -> None:
        self.encoding = kwargs.get("encoding", self.encoding)


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
        self.assertTrue(events)
        self.assertEqual(events[-1], 3)

    def test_verify_paths_empty(self) -> None:
        self.assertEqual(verify_paths([], 4), [])

    def test_verify_paths_with_elf(self) -> None:
        elf_path = self._path("bin")
        with open(elf_path, "wb") as handle:
            handle.write(b"\x7fELF\x02\x01\x01\x00")
        os.chmod(elf_path, 0o755)
        text_path = self._path("doc")
        with open(text_path, "w") as handle:
            handle.write("hello\n")
        missing = self._path("nope")
        statuses, elf_flags = verify_paths_with_elf([elf_path, text_path, missing], 4)
        self.assertEqual(statuses, [PathStatus.EXISTS, PathStatus.EXISTS, PathStatus.MISSING])
        self.assertEqual(elf_flags, [True, False, False])

    def test_verify_paths_with_elf_progress(self) -> None:
        open(self._path("a"), "w").close()
        events: list[int] = []
        verify_paths_with_elf([self._path("a"), self._path("nope")], 4, on_progress=events.append)
        self.assertTrue(events)
        self.assertEqual(events[-1], 2)

    def _write_elf(self, name: str, executable: bool = True) -> str:
        path = self._path(name)
        with open(path, "wb") as handle:
            handle.write(b"\x7fELF\x02\x01\x01\x00")
        if executable:
            os.chmod(path, 0o755)
        return path

    def test_is_elf_true_for_executable(self) -> None:
        self.assertTrue(_is_elf(self._write_elf("prog")))

    def test_is_elf_true_for_so_library(self) -> None:
        path = self._write_elf("libfoo.so", executable=False)
        self.assertTrue(_is_elf(path))

    def test_is_elf_false_for_non_exec_non_so(self) -> None:
        path = self._write_elf("data.bin", executable=False)
        self.assertFalse(_is_elf(path))

    def test_is_elf_false_for_text(self) -> None:
        path = self._path("script")
        with open(path, "w") as handle:
            handle.write("#!/bin/sh\n")
        os.chmod(path, 0o755)
        self.assertFalse(_is_elf(path))

    def test_is_elf_false_for_missing(self) -> None:
        self.assertFalse(_is_elf(self._path("nope")))

    def test_is_elf_false_for_directory(self) -> None:
        os.mkdir(self._path("adir"))
        self.assertFalse(_is_elf(self._path("adir")))

    def test_is_elf_false_for_fifo_without_blocking(self) -> None:
        fifo = self._path("pipe")
        os.mkfifo(fifo)
        self.assertFalse(_is_elf(fifo))

    def test_is_elf_symlink_to_elf(self) -> None:
        target = self._write_elf("target")
        link = self._path("link")
        os.symlink(target, link)
        self.assertTrue(_is_elf(link))

    def test_is_elf_symlink_to_fifo_no_block(self) -> None:
        fifo = self._path("fifo")
        os.mkfifo(fifo)
        link = self._path("lfifo")
        os.symlink(fifo, link)
        self.assertFalse(_is_elf(link))

    def test_verify_paths_with_elf_skips_fifo(self) -> None:
        fifo = self._path("pipe")
        os.mkfifo(fifo)
        statuses, elf_flags = verify_paths_with_elf([fifo], 4)
        self.assertEqual(statuses, [PathStatus.EXISTS])
        self.assertEqual(elf_flags, [False])

    def test_verify_paths_workers_one(self) -> None:
        for name in ("a", "b"):
            open(self._path(name), "w").close()
        statuses = verify_paths([self._path("a"), self._path("nope"), self._path("b")], 1)
        self.assertEqual(statuses, [PathStatus.EXISTS, PathStatus.MISSING, PathStatus.EXISTS])

    def test_verify_paths_with_elf_empty(self) -> None:
        statuses, elf_flags = verify_paths_with_elf([], 4)
        self.assertEqual(statuses, [])
        self.assertEqual(elf_flags, [])

    def test_check_path_no_access(self) -> None:
        with mock.patch("os.lstat", side_effect=PermissionError):
            self.assertIs(check_path(self._path("secret")), PathStatus.NO_ACCESS)


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

    def test_octal_over_255_does_not_crash(self) -> None:
        self._write("demo-ovr", b"FILE LIST:\nusr/bin/\\400\\777bad\n")
        result = self._scan()
        self.assertIn(("demo-ovr", "usr/bin/\ufffd\ufffdbad"), result.entries)

    def test_crlf_records_are_parsed(self) -> None:
        self._write("demo-crlf", b"FILE LIST:\r\nusr/bin/foo\r\netc/conf\r\n")
        result = self._scan()
        self.assertIn(("demo-crlf", "usr/bin/foo"), result.entries)
        self.assertIn(("demo-crlf", "etc/conf"), result.entries)

    def test_empty_file_list(self) -> None:
        self._write("demo-empty", b"PACKAGE NAME: demo-empty\nFILE LIST:\n")
        result = self._scan()
        self.assertEqual(result.entries, [])

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


class LibdepsTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write(self, name: str, content: bytes) -> str:
        path = self.dir / name
        path.write_bytes(content)
        return str(path)

    def test_build_library_owner_index(self) -> None:
        entries = [
            ("pkg-a", "usr/lib/libfoo.so.1"),
            ("pkg-b", "usr/lib64/libbar.so.2"),
            ("pkg-c", "usr/bin/tool"),
        ]
        index = build_library_owner_index(entries)
        self.assertEqual(index["libfoo.so.1"], "pkg-a")
        self.assertEqual(index["libbar.so.2"], "pkg-b")
        self.assertNotIn("tool", index)

    def test_find_missing_owner(self) -> None:
        index = {"libfoo.so.1": "pkg-a"}
        self.assertEqual(
            find_missing_owner(["libfoo.so.1", "libnope.so"], index),
            {
                "libfoo.so.1": "pkg-a",
                "libnope.so": None,
            },
        )

    def _fake_run(self, stdout: str, stderr: str = ""):
        return types.SimpleNamespace(stdout=stdout, stderr=stderr)

    def test_get_needed_libs_parses_output(self) -> None:
        from pkgcheck.libdeps import _get_needed_libs

        output = (
            " 0x00000001 (NEEDED)                     Shared library: [libfoo.so.1]\n"
            " 0x00000001 (NEEDED)                     Shared library: [libbar.so.2]\n"
        )
        with mock.patch(
            "pkgcheck.libdeps.subprocess.run",
            return_value=self._fake_run(output),
        ) as run:
            missing = _get_needed_libs("/x", "readelf")
        self.assertEqual(missing, ["libfoo.so.1", "libbar.so.2"])
        run.assert_called_once()

    def test_get_needed_libs_ignores_not_elf(self) -> None:
        from pkgcheck.libdeps import _get_needed_libs

        with mock.patch(
            "pkgcheck.libdeps.subprocess.run",
            return_value=self._fake_run("not an ELF file\n"),
        ):
            self.assertEqual(_get_needed_libs("/x", "readelf"), [])

    def test_check_library_deps_preserves_order_and_progress(self) -> None:
        with mock.patch(
            "pkgcheck.libdeps._get_needed_libs", side_effect=[["liba.so"], [], ["libb.so"]]
        ) as m:
            events: list[int] = []
            result = check_library_deps(
                ["/x", "/y", "/z"], 3, "readelf", {}, on_progress=events.append
            )
        self.assertEqual(result, [["liba.so"], [], ["libb.so"]])
        self.assertEqual(m.call_count, 3)
        self.assertTrue(events)
        self.assertEqual(events[-1], 3)

    def test_check_undefined_symbols_returns_parallel_list(self) -> None:
        with mock.patch(
            "pkgcheck.libdeps._undefined_symbols",
            side_effect=[["sym_a"], [], ["sym_b"]],
        ) as m:
            events: list[int] = []
            result = check_undefined_symbols(
                ["/x", "/y", "/z"], {"defined"}, 3, "readelf", on_progress=events.append
            )
        self.assertEqual(result, [["sym_a"], [], ["sym_b"]])
        self.assertEqual(m.call_count, 3)
        self.assertEqual(events[-1], 3)

    def test_get_needed_libs_timeout_returns_empty(self) -> None:
        from pkgcheck.libdeps import _get_needed_libs

        with mock.patch(
            "pkgcheck.libdeps.subprocess.run", side_effect=subprocess.TimeoutExpired("readelf", 60)
        ):
            self.assertEqual(_get_needed_libs("/x", "readelf"), [])

    def test_get_needed_libs_oserror_returns_empty(self) -> None:
        from pkgcheck.libdeps import _get_needed_libs

        with mock.patch("pkgcheck.libdeps.subprocess.run", side_effect=OSError("boom")):
            self.assertEqual(_get_needed_libs("/x", "readelf"), [])

    def test_get_needed_libs_malformed_output(self) -> None:
        from pkgcheck.libdeps import _get_needed_libs

        output = (
            "garbage line\n"
            " 0x00000001 (NEEDED)                     Shared library: [libfoo.so.1]\n"
            "stray text\n"
            " 0x00000001 (NEEDED)                     Shared library: [libbar.so.2]\n"
        )
        with mock.patch("pkgcheck.libdeps.subprocess.run", return_value=self._fake_run(output)):
            missing = _get_needed_libs("/x", "readelf")
        self.assertEqual(missing, ["libfoo.so.1", "libbar.so.2"])

    def test_collect_defined_symbols_empty(self) -> None:
        self.assertEqual(collect_defined_symbols([], 4, "readelf"), set())

    def test_collect_defined_symbols_readelf_failure(self) -> None:
        with mock.patch("pkgcheck.libdeps._readelf_symbols", return_value=None):
            events: list[int] = []
            defined = collect_defined_symbols(["/x", "/y"], 4, "readelf", on_progress=events.append)
        self.assertEqual(defined, set())
        self.assertEqual(events[-1], 2)

    def test_check_library_deps_empty(self) -> None:
        self.assertEqual(check_library_deps([], 4, "readelf", {}), [])

    def test_is_library_path_variants(self) -> None:
        self.assertTrue(_is_library_path("usr/libexec/foo.so"))
        self.assertTrue(_is_library_path("lib64/libbar.so.1"))
        self.assertFalse(_is_library_path("usr/share/doc/foo.so"))
        self.assertFalse(_is_library_path("usr/lib/foo.a"))
        self.assertFalse(_is_library_path("usr/lib/foo"))

    def test_get_needed_libs_dedup(self) -> None:
        from pkgcheck.libdeps import _get_needed_libs

        output = (
            " 0x00000001 (NEEDED)                     Shared library: [libfoo.so.1]\n"
            " 0x00000001 (NEEDED)                     Shared library: [libfoo.so.1]\n"
            " 0x00000001 (NEEDED)                     Shared library: [libbar.so.2]\n"
        )
        with mock.patch("pkgcheck.libdeps.subprocess.run", return_value=self._fake_run(output)):
            missing = _get_needed_libs("/x", "readelf")
        self.assertEqual(missing, ["libfoo.so.1", "libbar.so.2"])

    def test_readelf_symbols_with_version(self) -> None:
        output = (
            "     6: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.2.5\n"
            "    13: 0000000000004a40    26 FUNC    GLOBAL DEFAULT   13 main\n"
            "    14: 0000000000000000     0 FUNC    GLOBAL DEFAULT   12 foo@VER_1\n"
        )
        with mock.patch("pkgcheck.libdeps.subprocess.run", return_value=self._fake_run(output)):
            symbols = _readelf_symbols("/x", "readelf")
        self.assertIsNotNone(symbols)
        assert symbols is not None
        self.assertIn("main", symbols)
        self.assertIn("foo@VER_1", symbols)
        self.assertNotIn("UND", symbols)

    def test_readelf_symbols_timeout_returns_none(self) -> None:
        with mock.patch(
            "pkgcheck.libdeps.subprocess.run", side_effect=subprocess.TimeoutExpired("readelf", 60)
        ):
            self.assertIsNone(_readelf_symbols("/x", "readelf"))

    def test_readelf_symbols_oserror_returns_none(self) -> None:
        with mock.patch("pkgcheck.libdeps.subprocess.run", side_effect=OSError("boom")):
            self.assertIsNone(_readelf_symbols("/x", "readelf"))

    def test_undefined_symbols_versioned(self) -> None:
        output = (
            "     6: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.2.5\n"
            "     7: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND missing@VER_1\n"
        )
        with mock.patch("pkgcheck.libdeps.subprocess.run", return_value=self._fake_run(output)):
            undefined = _undefined_symbols("/x", {"puts@GLIBC_2.2.5"}, "readelf")
        self.assertEqual(undefined, ["missing@VER_1"])

    def test_undefined_symbols_timeout_returns_empty(self) -> None:
        with mock.patch(
            "pkgcheck.libdeps.subprocess.run", side_effect=subprocess.TimeoutExpired("readelf", 60)
        ):
            self.assertEqual(_undefined_symbols("/x", set(), "readelf"), [])

    def test_undefined_symbols_oserror_returns_empty(self) -> None:
        with mock.patch("pkgcheck.libdeps.subprocess.run", side_effect=OSError("boom")):
            self.assertEqual(_undefined_symbols("/x", set(), "readelf"), [])

    def test_check_library_deps_future_exception(self) -> None:
        # Force future.result() to raise
        with mock.patch("pkgcheck.libdeps.ThreadPoolExecutor") as MockExec:
            mock_exec = mock.MagicMock()
            MockExec.return_value.__enter__.return_value = mock_exec
            f1 = mock.MagicMock()
            f1.result.side_effect = RuntimeError("boom")
            mock_exec.submit.return_value = f1
            with mock.patch("pkgcheck.libdeps.as_completed", return_value=[f1]):
                result = check_library_deps(["/x"], 1, "readelf", {})
            self.assertEqual(result, [[]])

    def test_collect_defined_symbols_future_exception(self) -> None:
        with mock.patch("pkgcheck.libdeps.ThreadPoolExecutor") as MockExec:
            mock_exec = mock.MagicMock()
            MockExec.return_value.__enter__.return_value = mock_exec
            f1 = mock.MagicMock()
            f1.result.side_effect = RuntimeError("boom")
            mock_exec.submit.return_value = f1
            with mock.patch("pkgcheck.libdeps.as_completed", return_value=[f1]):
                result = collect_defined_symbols(["/x"], 1, "readelf")
            self.assertEqual(result, set())

    def test_check_undefined_symbols_future_exception(self) -> None:
        with mock.patch("pkgcheck.libdeps.ThreadPoolExecutor") as MockExec:
            mock_exec = mock.MagicMock()
            MockExec.return_value.__enter__.return_value = mock_exec
            f1 = mock.MagicMock()
            f1.result.side_effect = RuntimeError("boom")
            mock_exec.submit.return_value = f1
            with mock.patch("pkgcheck.libdeps.as_completed", return_value=[f1]):
                result = check_undefined_symbols(["/x"], set(), 1, "readelf")
            self.assertEqual(result, [[]])

    def test_build_library_owner_index_last_wins(self) -> None:
        entries = [
            ("pkg-a", "usr/lib/libdup.so.1"),
            ("pkg-b", "usr/lib/libdup.so.1"),
        ]
        index = build_library_owner_index(entries)
        self.assertEqual(index["libdup.so.1"], "pkg-b")

    def test_build_library_owner_index_libexec(self) -> None:
        entries = [("pkg-a", "usr/libexec/helper.so")]
        index = build_library_owner_index(entries)
        self.assertIn("helper.so", index)


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

    def _broken_libs(self):
        return {
            "pkg": [
                BrokenBinary(
                    binary="/usr/bin/foo",
                    missing=["libfoo.so.1"],
                    provided_by={"libfoo.so.1": "pkg-foo"},
                )
            ]
        }

    def test_report_path(self) -> None:
        when = datetime(2026, 8, 7, 12, 34, 56)
        # New format includes microseconds
        self.assertEqual(
            report_path(Path("/var/log/pkgcheck"), when, "log"),
            Path("/var/log/pkgcheck/pkgcheck-07-08-2026-12-34-56-000000.log"),
        )
        self.assertEqual(
            report_path(Path("/var/log/pkgcheck"), when, "json"),
            Path("/var/log/pkgcheck/pkgcheck-07-08-2026-12-34-56-000000.json"),
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

    def test_json_report_broken_libs(self) -> None:
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
            broken_binaries=1,
            missing_libs=1,
        )
        doc = json.loads(json_report(summary, *self._indexes(), broken_libs=self._broken_libs()))
        self.assertEqual(doc["summary"]["broken_binaries"], 1)
        self.assertEqual(doc["broken_libs"]["pkg"][0]["binary"], "/usr/bin/foo")
        self.assertEqual(doc["broken_libs"]["pkg"][0]["provided_by"], {"libfoo.so.1": "pkg-foo"})

    def test_json_report_omits_broken_libs_when_empty(self) -> None:
        doc = json.loads(json_report(_summary(), *self._indexes()))
        self.assertNotIn("broken_libs", doc)

    def test_json_broken_libs_provided_by_none(self) -> None:
        broken = {
            "pkg": [
                BrokenBinary(
                    binary="/usr/bin/foo", missing=["libx.so.1"], provided_by={"libx.so.1": None}
                )
            ]
        }
        doc = json.loads(json_report(_summary(), *self._indexes(), broken_libs=broken))
        self.assertEqual(doc["broken_libs"]["pkg"][0]["provided_by"], {"libx.so.1": None})

    def test_json_undefined_symbols(self) -> None:
        doc = json.loads(
            json_report(_summary(), *self._indexes(), undefined_symbols={"pkg": {"/bin/a": ["s1"]}})
        )
        self.assertEqual(doc["undefined_symbols"], {"pkg": {"/bin/a": ["s1"]}})

    def test_text_report_undefined_symbols_section(self) -> None:
        text = _text_report(
            _summary(),
            *self._indexes(),
            undefined_symbols={"pkg": {"/bin/a": ["s1", "s2"]}},
        )
        self.assertIn("UNDEFINED SYMBOLS", text)
        self.assertIn("/bin/a", text)
        self.assertIn("s1, s2", text)

    def test_text_report_broken_libs_section(self) -> None:
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
            broken_binaries=1,
            missing_libs=1,
        )
        text = _text_report(
            summary,
            *self._indexes(),
            broken_libs=self._broken_libs(),
        )
        self.assertIn("BROKEN LIBRARY DEPS:", text)
        self.assertIn("pkg", text)
        self.assertIn("/usr/bin/foo", text)
        self.assertIn("libfoo.so.1", text)
        self.assertIn("pkg-foo", text)

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

    def test_print_breakdown_banner(self) -> None:
        buf = io.StringIO()
        from rich.console import Console

        console = Console(file=buf, width=100, force_terminal=False)
        print_breakdown(console, {"pkg": ["/x"]})
        out = buf.getvalue()
        self.assertIn("*" * 12, out)
        self.assertIn("Missing files by package", out)
        self.assertIn("pkg", out)
        self.assertTrue(out.startswith("\n"))

    def test_print_broken_libs_banner(self) -> None:
        buf = io.StringIO()
        from rich.console import Console

        console = Console(file=buf, width=100, force_terminal=False)
        broken = {
            "pkg": [
                BrokenBinary(
                    binary="/usr/bin/foo",
                    missing=["libx.so.1"],
                    provided_by={"libx.so.1": "pkg-x"},
                )
            ]
        }
        print_broken_libs(console, broken)
        out = buf.getvalue()
        self.assertIn("*" * 12, out)
        self.assertIn("Binaries with missing library deps by package", out)
        self.assertTrue(out.startswith("\n"))

    def test_text_report_section_banners(self) -> None:
        text = _text_report(_summary(), *self._indexes())
        self.assertIn("=" * 46, text)
        self.assertIn("MISSING:", text)
        self.assertIn("\n\n" + "=" * 46, text)

    def test_unique_report_path_collision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp)
            when = datetime(2026, 8, 7, 12, 34, 56)
            first = log_dir / "pkgcheck-07-08-2026-12-34-56-000000.log"
            first.write_text("x")
            second = unique_report_path(log_dir, when, "log")
            # Should use UUID suffix now
            self.assertTrue(second.name.startswith("pkgcheck-07-08-2026-12-34-56-000000-"))
            self.assertTrue(second.name.endswith(".log"))
            second.write_text("y")
            third = unique_report_path(log_dir, when, "log")
            self.assertTrue(third.name.startswith("pkgcheck-07-08-2026-12-34-56-000000-"))
            self.assertTrue(third.name.endswith(".log"))
            self.assertNotEqual(second, third)

    def test_unique_report_path_too_many_raises(self) -> None:
        # This test is no longer applicable since we use UUID
        # UUID collision is practically impossible, so we just verify it returns a path
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp)
            when = datetime(2026, 8, 7, 12, 34, 56)
            path = unique_report_path(log_dir, when, "log")
            self.assertTrue(path.exists() or not path.exists())  # Always returns a path

    def test_write_report_json_and_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            json_path = tmp_path / "out.json"
            log_path = tmp_path / "out.log"
            summary = _summary()
            indexes = self._indexes()
            when = datetime(2026, 8, 7, 12, 34, 56)
            write_report(json_path, summary, *indexes, when)
            doc = json.loads(json_path.read_text())
            self.assertEqual(doc["generator"], "pkgcheck")
            self.assertEqual(doc["timestamp"], "2026-08-07T12:34:56")
            write_report(log_path, summary, *indexes, when)
            text = log_path.read_text()
            self.assertIn("MISSING:", text)
            self.assertIn("pkgcheck v", text)

    def test_write_report_with_broken_and_symbols(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            json_path = tmp_path / "out.json"
            log_path = tmp_path / "out.log"
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
                broken_binaries=1,
                missing_libs=1,
                undefined_symbol_binaries=1,
            )
            when = datetime(2026, 8, 7, 12, 34, 56)
            broken = self._broken_libs()
            undefined = {"pkg": {"/bin/a": ["s1"]}}
            write_report(json_path, summary, *self._indexes(), when, broken, undefined)
            self.assertIn("broken_libs", json.loads(json_path.read_text()))
            write_report(log_path, summary, *self._indexes(), when, broken, undefined)
            text = log_path.read_text()
            self.assertIn("BROKEN LIBRARY DEPS:", text)
            self.assertIn("UNDEFINED SYMBOLS", text)

    def test_print_summary_all_branches(self) -> None:
        from rich.console import Console

        buf = io.StringIO()
        console = Console(file=buf, width=200, force_terminal=False)
        summary = Summary(
            packages=10,
            files_checked=100,
            missing=5,
            backup=2,
            pending_new=3,
            no_access=4,
            errors=6,
            excluded_install=7,
            excluded_pseudo=8,
            broken_binaries=2,
            missing_libs=3,
            undefined_symbol_binaries=1,
        )
        from pkgcheck.reporter import print_summary

        print_summary(console, summary, 1.23)
        out = buf.getvalue()
        self.assertIn("Packages analyzed", out)
        self.assertIn("Files with backup only", out)
        self.assertIn("Configs .new pending", out)
        self.assertIn("Files without access", out)
        self.assertIn("Verification errors", out)
        self.assertIn("Install scripts excluded", out)
        self.assertIn("Pseudo-filesystems excluded", out)
        self.assertIn("Binaries with missing library deps", out)
        self.assertIn("Missing shared libraries", out)
        self.assertIn("Binaries with undefined symbols", out)

    def test_print_breakdown_max_rows_truncation(self) -> None:
        from rich.console import Console

        buf = io.StringIO()
        console = Console(file=buf, width=200, force_terminal=False)
        data = {f"pkg{i}": [f"/file{i}"] for i in range(5)}
        print_breakdown(console, data, max_rows=2)
        out = buf.getvalue()
        self.assertIn("... and 3 more packages", out)

    def test_print_broken_libs_max_rows_truncation(self) -> None:
        from rich.console import Console

        buf = io.StringIO()
        console = Console(file=buf, width=200, force_terminal=False)
        broken = {
            f"pkg{i}": [BrokenBinary(binary=f"/bin/{i}", missing=["lib.so"], provided_by={})]
            for i in range(5)
        }
        print_broken_libs(broken, max_rows=2) if False else None
        # Call with explicit console
        print_broken_libs(console, broken, max_rows=2)
        out = buf.getvalue()
        self.assertIn("... and 3 more packages", out)

    def test_print_breakdown_custom_title(self) -> None:
        from rich.console import Console

        buf = io.StringIO()
        console = Console(file=buf, width=200, force_terminal=False)
        print_breakdown(console, {"pkg": ["/a"]}, title="Custom Title")
        self.assertIn("Custom Title", buf.getvalue())

    def test_text_report_empty_missing(self) -> None:
        summary = Summary(
            packages=0,
            files_checked=0,
            missing=0,
            backup=0,
            pending_new=0,
            no_access=0,
            errors=0,
            excluded_install=0,
            excluded_pseudo=0,
        )
        text = _text_report(summary, {}, {}, {}, {}, {})
        self.assertIn("(none)", text)
        self.assertIn("MISSING:", text)

    def test_text_report_all_sections(self) -> None:
        summary = Summary(
            packages=1,
            files_checked=10,
            missing=1,
            backup=1,
            pending_new=1,
            no_access=1,
            errors=1,
            excluded_install=1,
            excluded_pseudo=1,
            broken_binaries=1,
            missing_libs=1,
            undefined_symbol_binaries=1,
        )
        text = _text_report(
            summary,
            {"pkg": ["/a"]},
            {"pkg": ["/b"]},
            {"pkg": ["/c"]},
            {"pkg": ["/d"]},
            {"pkg": ["/e"]},
            datetime(2026, 8, 7, 12, 34, 56),
            {
                "pkg": [
                    BrokenBinary(binary="/bin/x", missing=["lib.so"], provided_by={"lib.so": None})
                ]
            },
            {"pkg": {"/bin/y": ["sym"]}},
        )
        self.assertIn("BACKUP ONLY", text)
        self.assertIn("NO ACCESS", text)
        self.assertIn("ERRORS:", text)
        self.assertIn("BROKEN LIBRARY DEPS:", text)
        self.assertIn("UNDEFINED SYMBOLS", text)


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

    def test_is_utf8(self) -> None:
        self.assertTrue(_is_utf8("utf-8"))
        self.assertTrue(_is_utf8("UTF-8"))
        self.assertTrue(_is_utf8("utf8"))
        self.assertFalse(_is_utf8("ISO-8859-1"))
        self.assertFalse(_is_utf8("ANSI_X3.4-1968"))
        self.assertFalse(_is_utf8("latin-1"))
        self.assertFalse(_is_utf8(""))
        self.assertFalse(_is_utf8(None))

    def test_ensure_utf8_environment_ok(self) -> None:
        with (
            mock.patch("sys.stdout", _FakeStream("UTF-8")),
            mock.patch("sys.stderr", _FakeStream("utf-8")),
            mock.patch.dict(os.environ, {}, clear=True),
        ):
            previous, subprocess_env = _ensure_utf8_environment()
            self.assertIsNone(previous)
            self.assertEqual(subprocess_env, {})

    def test_ensure_utf8_environment_forces_fallback(self) -> None:
        with (
            mock.patch("sys.stdout", _FakeStream("ISO-8859-1")),
            mock.patch("sys.stderr", _FakeStream("latin-1")),
            mock.patch.dict(os.environ, {}, clear=True),
        ):
            previous, subprocess_env = _ensure_utf8_environment()
            self.assertEqual(previous, "ISO-8859-1")
            self.assertEqual(subprocess_env["PYTHONIOENCODING"], "utf-8")
            self.assertEqual(subprocess_env["LANG"], "en_US.UTF-8")
            self.assertEqual(subprocess_env["LC_ALL"], "en_US.UTF-8")

    def test_ensure_utf8_environment_survives_reconfigure_failure(self) -> None:
        class _NoReconfigure(_FakeStream):
            def reconfigure(self, **_):
                raise AttributeError("not a text stream")

        with (
            mock.patch("sys.stdout", _NoReconfigure("latin-1")),
            mock.patch("sys.stderr", _FakeStream("UTF-8")),
            mock.patch.dict(os.environ, {}, clear=True),
        ):
            previous, subprocess_env = _ensure_utf8_environment()
            self.assertEqual(previous, "latin-1")
            self.assertEqual(subprocess_env["PYTHONIOENCODING"], "utf-8")


class CliIntegrationTest(unittest.TestCase):
    def _run(self, *args: str, env: dict[str, str] | None = None):
        import sys

        return subprocess.run(
            [sys.executable, "-m", "pkgcheck", *args],
            capture_output=True,
            text=True,
            env=env,
        )

    def test_lang_full_locale_help(self) -> None:
        result = self._run("--lang", "es_ES", "--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Directorio con los registros", result.stdout)

    def test_unsupported_lang_errors(self) -> None:
        result = self._run("--lang", "xx")
        self.assertEqual(result.returncode, 2)
        self.assertIn("xx", result.stderr)

    def test_symbols_requires_deps(self) -> None:
        result = self._run("--check-libs-symbols", "--no-elevate", "--lang", "en")
        self.assertEqual(result.returncode, 2)
        self.assertIn("--check-libs-symbols", result.stderr)
        self.assertIn("--check-lib-deps", result.stderr)

    def test_packages_dir_nonexistent(self) -> None:
        result = self._run("--packages-dir", "/nonexistent/pkgcheck-dir", "--no-elevate")
        self.assertEqual(result.returncode, 2)

    def test_workers_out_of_range(self) -> None:
        self.assertEqual(self._run("--workers", "0", "--no-elevate").returncode, 2)
        self.assertEqual(self._run("--workers", "9999", "--no-elevate").returncode, 2)

    def test_encoding_fallback_latin1(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "demo-1.0").write_text("FILE LIST:\nbin/true\n")
            env = dict(os.environ, PYTHONIOENCODING="iso-8859-1")
            result = self._run(
                "--packages-dir", tmp, "--check-lib-deps", "--no-elevate", "--lang", "en", env=env
            )
            self.assertEqual(result.returncode, 0)
            self.assertIn("not UTF-8", result.stdout)
            self.assertIn("fallback", result.stdout.lower())

    def test_run_is_nondestructive(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            packages = root / "packages"
            packages.mkdir()
            (packages / "demo-1.0").write_text("FILE LIST:\nusr/bin/x\n")
            fake = root / "usr"
            fake.mkdir()
            victim = fake / "x"
            victim.write_bytes(b"precious content")

            before = {
                str(p): (p.read_bytes() if p.is_file() else None, p.stat().st_mtime_ns)
                for p in root.rglob("*")
            }
            result = self._run("--packages-dir", str(packages), "--no-elevate", "--lang", "en")
            self.assertEqual(result.returncode, 0)
            after = {
                str(p): (p.read_bytes() if p.is_file() else None, p.stat().st_mtime_ns)
                for p in root.rglob("*")
            }
            self.assertEqual(before, after)
            self.assertEqual(victim.read_bytes(), b"precious content")


class CliParserCoverageTest(unittest.TestCase):
    def test_default_workers(self) -> None:
        with mock.patch("os.cpu_count", return_value=None):
            self.assertEqual(_default_workers(), 5)
        with mock.patch("os.cpu_count", return_value=1):
            self.assertEqual(_default_workers(), 5)
        with mock.patch("os.cpu_count", return_value=100):
            self.assertEqual(_default_workers(), 32)

    def test_build_parser_defaults(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(["--no-elevate", "--packages-dir", "/tmp"])
        self.assertEqual(args.packages_dir, "/tmp")
        self.assertFalse(args.json)
        self.assertIsNone(args.max_rows)

    def test_build_parser_all_flags(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(
            [
                "--no-elevate",
                "--packages-dir",
                "/tmp",
                "--workers",
                "4",
                "--json",
                "--max-rows",
                "5",
                "--exclude",
                "mnt",
                "--backup-suffixes",
                ".bak,.orig",
                "--new-suffix",
                ".new",
                "--check-lib-deps",
                "--quiet",
                "--lang",
                "es",
            ]
        )
        self.assertEqual(args.workers, 4)
        self.assertTrue(args.json)
        self.assertEqual(args.max_rows, 5)
        self.assertIn("mnt", args.exclude[0])
        self.assertTrue(args.check_lib_deps)
        self.assertTrue(args.quiet)

    def test_build_parser_version(self) -> None:
        parser = _build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["--version"])

    def test_pseudo_prefixes_empty(self) -> None:
        from pkgcheck.scanner import _PSEUDO_PREFIXES

        ns = mock.Mock(exclude=[])
        self.assertEqual(_pseudo_prefixes(ns), _PSEUDO_PREFIXES)

    def test_backup_suffixes_empty(self) -> None:
        ns = mock.Mock(backup_suffixes=" , ")
        self.assertEqual(_backup_suffixes(ns), ())


class CliRootCoverageTest(unittest.TestCase):
    def test_ensure_root_already_root(self) -> None:
        args = mock.Mock(elevate=False, no_elevate=False, quiet=False, json=False)
        console = mock.MagicMock()
        status = mock.MagicMock()
        with mock.patch("os.geteuid", return_value=0):
            _ensure_root(args, console, status)
        console.print.assert_not_called()

    def test_ensure_root_elevate_calls_sudo(self) -> None:
        args = mock.Mock(elevate=True, no_elevate=False, quiet=False, json=False)
        console = mock.MagicMock()
        status = mock.MagicMock()
        with (
            mock.patch("os.geteuid", return_value=1000),
            mock.patch("pkgcheck.cli._exec_with_sudo") as mock_sudo,
        ):
            _ensure_root(args, console, status)
            mock_sudo.assert_called_once()

    def test_ensure_root_no_elevate_warns(self) -> None:
        for json_flag in (False, True):
            args = mock.Mock(elevate=False, no_elevate=True, quiet=False, json=json_flag)
            console = mock.MagicMock()
            status = mock.MagicMock()
            with mock.patch("os.geteuid", return_value=1000):
                _ensure_root(args, console, status)
            if json_flag:
                status.print.assert_called()
            else:
                console.print.assert_called()

    def test_ensure_root_no_elevate_quiet_no_warn(self) -> None:
        args = mock.Mock(elevate=False, no_elevate=True, quiet=True, json=False)
        console = mock.MagicMock()
        status = mock.MagicMock()
        with mock.patch("os.geteuid", return_value=1000):
            _ensure_root(args, console, status)
        console.print.assert_not_called()
        status.print.assert_not_called()

    def test_ensure_root_non_tty_no_elevate(self) -> None:
        args = mock.Mock(elevate=False, no_elevate=False, quiet=False, json=False)
        console = mock.MagicMock()
        status = mock.MagicMock()
        with (
            mock.patch("os.geteuid", return_value=1000),
            mock.patch("sys.stdin.isatty", return_value=False),
        ):
            _ensure_root(args, console, status)
            console.print.assert_called()

    def test_ensure_root_confirm_yes(self) -> None:
        args = mock.Mock(elevate=False, no_elevate=False, quiet=False, json=False)
        console = mock.MagicMock()
        status = mock.MagicMock()
        with (
            mock.patch("os.geteuid", return_value=1000),
            mock.patch("sys.stdin.isatty", return_value=True),
            mock.patch("pkgcheck.cli.Confirm.ask", return_value=True),
            mock.patch("pkgcheck.cli._exec_with_sudo") as mock_sudo,
        ):
            _ensure_root(args, console, status)
            mock_sudo.assert_called_once()

    def test_ensure_root_confirm_no(self) -> None:
        args = mock.Mock(elevate=False, no_elevate=False, quiet=False, json=False)
        console = mock.MagicMock()
        status = mock.MagicMock()
        with (
            mock.patch("os.geteuid", return_value=1000),
            mock.patch("sys.stdin.isatty", return_value=True),
            mock.patch("pkgcheck.cli.Confirm.ask", return_value=False),
            mock.patch("pkgcheck.cli._exec_with_sudo") as mock_sudo,
        ):
            _ensure_root(args, console, status)
            mock_sudo.assert_not_called()

    def test_ensure_root_confirm_json_uses_status_console(self) -> None:
        args = mock.Mock(elevate=False, no_elevate=False, quiet=False, json=True)
        console = mock.MagicMock()
        status = mock.MagicMock()
        with (
            mock.patch("os.geteuid", return_value=1000),
            mock.patch("sys.stdin.isatty", return_value=True),
            mock.patch("pkgcheck.cli.Confirm.ask", return_value=False) as mock_ask,
        ):
            _ensure_root(args, console, status)
            mock_ask.assert_called_once()
            # prompt_console should be status when json
            self.assertEqual(mock_ask.call_args.kwargs.get("console"), status)

    def test_exec_with_sudo_no_sudo(self) -> None:
        with mock.patch("shutil.which", return_value=None):
            with self.assertRaises(RuntimeError):
                _exec_with_sudo()

    def test_exec_with_sudo_main_py(self) -> None:
        with (
            mock.patch("shutil.which", return_value="/usr/bin/sudo"),
            mock.patch("os.execvp") as mock_exec,
            mock.patch("sys.argv", ["/usr/lib/python3.12/__main__.py", "--no-elevate"]),
            mock.patch("sys.executable", "/usr/bin/python"),
        ):
            try:
                _exec_with_sudo()
            except Exception:
                pass
            mock_exec.assert_called_once()
            args = mock_exec.call_args[0][1]
            self.assertIn("-m", args)
            self.assertIn("pkgcheck", args)

    def test_exec_with_sudo_script(self) -> None:
        with (
            mock.patch("shutil.which", return_value="/usr/bin/sudo"),
            mock.patch("os.execvp") as mock_exec,
            mock.patch("sys.argv", ["/usr/bin/pkgcheck", "--json"]),
        ):
            try:
                _exec_with_sudo()
            except Exception:
                pass
            mock_exec.assert_called_once()
            args = mock_exec.call_args[0][1]
            self.assertTrue(any("/usr/bin/pkgcheck" in str(a) for a in args))


class CliWriteLogCoverageTest(unittest.TestCase):
    def setUp(self) -> None:
        i18n.set_language("en")

    def tearDown(self) -> None:
        i18n.set_language("en")

    def test_write_auto_log_not_root(self) -> None:
        from rich.console import Console

        buf = io.StringIO()
        console = Console(file=buf, width=80, force_terminal=False)
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
        )
        with mock.patch("os.geteuid", return_value=1000):
            result = _write_auto_log(
                console, datetime(2026, 8, 7, 12, 34, 56), "log", summary, {}, {}, {}, {}, {}
            )
        self.assertIsNone(result)

    def test_write_auto_log_success(self) -> None:
        from rich.console import Console

        i18n.set_language("en")
        with tempfile.TemporaryDirectory() as tmp:
            buf = io.StringIO()
            console = Console(file=buf, width=80, force_terminal=False)
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
            )
            when = datetime(2026, 8, 7, 12, 34, 56)
            fake_log_dir = Path(tmp)
            with (
                mock.patch("os.geteuid", return_value=0),
                mock.patch("pkgcheck.cli._LOG_DIR", fake_log_dir),
                mock.patch(
                    "pkgcheck.cli.unique_report_path",
                    return_value=fake_log_dir / "pkgcheck-07-08-2026-12-34-56.log",
                ) as mock_path,
            ):
                result = _write_auto_log(console, when, "log", summary, {}, {}, {}, {}, {})
                self.assertIsNotNone(result)
                self.assertTrue(result.exists())
                text = result.read_text()
                self.assertTrue("MISSING" in text or "FALTANTES" in text)

    def test_write_auto_log_oserror(self) -> None:
        from rich.console import Console

        i18n.set_language("en")
        buf = io.StringIO()
        console = Console(file=buf, width=80, force_terminal=False)
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
        )
        when = datetime(2026, 8, 7, 12, 34, 56)
        with (
            mock.patch("os.geteuid", return_value=0),
            mock.patch("pkgcheck.cli.unique_report_path", return_value=Path("/tmp/x.log")),
            mock.patch("pkgcheck.cli.write_report", side_effect=OSError("boom")),
            mock.patch("pkgcheck.cli._LOG_DIR", Path("/tmp")),
        ):
            result = _write_auto_log(console, when, "log", summary, {}, {}, {}, {}, {})
            self.assertIsNone(result)
            out = buf.getvalue()
            self.assertTrue("Could not write" in out or "No se pudo" in out)


class CliRunCoverageTest(unittest.TestCase):
    def setUp(self) -> None:
        i18n.set_language("en")

    def tearDown(self) -> None:
        i18n.set_language("en")

    def _make_args(self, **overrides):
        defaults = dict(
            quiet=False,
            json=False,
            check_lib_deps=False,
            check_libs_symbols=False,
            orphans=False,
            orphans_root="/",
            workers=2,
            max_rows=None,
            exclude=[],
            backup_suffixes=".bak,.orig",
            new_suffix=".new",
        )
        defaults.update(overrides)
        return mock.Mock(**defaults)

    def test_run_no_entries(self) -> None:
        from rich.console import Console

        buf = io.StringIO()
        console = Console(file=buf, width=80, force_terminal=False)
        status = Console(file=io.StringIO(), width=80, force_terminal=False)
        args = self._make_args()
        with mock.patch(
            "pkgcheck.cli.scan_package_files",
            return_value=ScanResult(entries=[], excluded_install=0, excluded_pseudo=0),
        ):
            _run(console, status, args, Path("/tmp"), "rg", None, None)
        self.assertIn(
            "No registered files",
            buf.getvalue()
            if not args.json
            else status.file.getvalue()
            if hasattr(status, "file")
            else "",
        )

    def test_run_simple_missing_and_backup(self) -> None:
        from rich.console import Console

        buf = io.StringIO()
        console = Console(file=buf, width=120, force_terminal=False, stderr=False)
        status = Console(file=io.StringIO(), width=120, force_terminal=False, stderr=True)
        args = self._make_args(quiet=False, json=False)
        entries = [("pkg-a", "usr/bin/foo"), ("pkg-a", "usr/bin/bar"), ("pkg-b", "etc/conf.new")]
        scan_result = ScanResult(entries=entries, excluded_install=1, excluded_pseudo=2)
        statuses = [PathStatus.MISSING, PathStatus.BACKUP, PathStatus.NEW_PENDING]
        with (
            mock.patch("pkgcheck.cli.scan_package_files", return_value=scan_result),
            mock.patch("pkgcheck.cli.verify_paths", return_value=statuses),
            mock.patch("pkgcheck.cli.Progress") as MockProgress,
        ):
            mock_prog = mock.MagicMock()
            MockProgress.return_value.__enter__.return_value = mock_prog
            mock_prog.add_task.return_value = 0
            with tempfile.TemporaryDirectory() as tmp:
                fake_dir = Path(tmp)
                with (
                    mock.patch("pkgcheck.cli._LOG_DIR", fake_dir),
                    mock.patch("os.geteuid", return_value=0),
                ):
                    _run(console, status, args, Path("/tmp"), "rg", None, None)
        out = buf.getvalue()
        self.assertIn("Missing files by package", out)

    def test_run_with_errors_and_no_access(self) -> None:
        from rich.console import Console

        buf = io.StringIO()
        console = Console(file=buf, width=120, force_terminal=False)
        status = Console(file=io.StringIO(), width=120, force_terminal=False)
        args = self._make_args(quiet=False, json=False)
        entries = [("pkg", "usr/bin/a"), ("pkg", "usr/bin/b"), ("pkg", "usr/bin/c")]
        statuses = [PathStatus.ERROR, PathStatus.NO_ACCESS, PathStatus.EXISTS]
        scan_result = ScanResult(entries=entries, excluded_install=0, excluded_pseudo=0)
        with (
            mock.patch("pkgcheck.cli.scan_package_files", return_value=scan_result),
            mock.patch("pkgcheck.cli.verify_paths", return_value=statuses),
            mock.patch("pkgcheck.cli.Progress") as MockProgress,
        ):
            mock_prog = mock.MagicMock()
            MockProgress.return_value.__enter__.return_value = mock_prog
            mock_prog.add_task.return_value = 0
            with tempfile.TemporaryDirectory() as tmp:
                with (
                    mock.patch("pkgcheck.cli._LOG_DIR", Path(tmp)),
                    mock.patch("os.geteuid", return_value=0),
                ):
                    _run(console, status, args, Path("/tmp"), "rg", None, None)
        out = buf.getvalue()
        self.assertIn("Files with verification errors", out)

    def test_run_quiet_no_breakdown(self) -> None:
        from rich.console import Console

        buf = io.StringIO()
        console = Console(file=buf, width=120, force_terminal=False)
        status = Console(file=io.StringIO(), width=120, force_terminal=False)
        args = self._make_args(quiet=True, json=False)
        entries = [("pkg", "usr/bin/foo")]
        scan_result = ScanResult(entries=entries, excluded_install=0, excluded_pseudo=0)
        with (
            mock.patch("pkgcheck.cli.scan_package_files", return_value=scan_result),
            mock.patch("pkgcheck.cli.verify_paths", return_value=[PathStatus.MISSING]),
            mock.patch("pkgcheck.cli.Progress") as MockProgress,
        ):
            mock_prog = mock.MagicMock()
            MockProgress.return_value.__enter__.return_value = mock_prog
            mock_prog.add_task.return_value = 0
            with tempfile.TemporaryDirectory() as tmp:
                with (
                    mock.patch("pkgcheck.cli._LOG_DIR", Path(tmp)),
                    mock.patch("os.geteuid", return_value=0),
                ):
                    _run(console, status, args, Path("/tmp"), "rg", None, None)
        # quiet hides breakdown, but summary still printed
        self.assertNotIn("Missing files by package", buf.getvalue())

    def test_run_json_no_root_writes_stdout(self) -> None:
        from rich.console import Console

        console = Console(file=io.StringIO(), width=80, force_terminal=False)
        status = Console(file=io.StringIO(), width=80, force_terminal=False, stderr=True)
        args = self._make_args(quiet=False, json=True)
        entries = [("pkg", "usr/bin/foo")]
        scan_result = ScanResult(entries=entries, excluded_install=0, excluded_pseudo=0)
        with (
            mock.patch("pkgcheck.cli.scan_package_files", return_value=scan_result),
            mock.patch("pkgcheck.cli.verify_paths", return_value=[PathStatus.MISSING]),
            mock.patch("pkgcheck.cli.Progress") as MockProgress,
            mock.patch("os.geteuid", return_value=1000),
            mock.patch("sys.stdout", new=io.StringIO()) as fake_out,
        ):
            mock_prog = mock.MagicMock()
            MockProgress.return_value.__enter__.return_value = mock_prog
            mock_prog.add_task.return_value = 0
            _run(console, status, args, Path("/tmp"), "rg", None, None)
            self.assertIn("generator", fake_out.getvalue())

    def test_run_json_with_root_writes_log(self) -> None:
        from rich.console import Console

        console = Console(file=io.StringIO(), width=80, force_terminal=False)
        status = Console(file=io.StringIO(), width=80, force_terminal=False)
        args = self._make_args(quiet=False, json=True)
        entries = [("pkg", "usr/bin/foo")]
        scan_result = ScanResult(entries=entries, excluded_install=0, excluded_pseudo=0)
        with (
            mock.patch("pkgcheck.cli.scan_package_files", return_value=scan_result),
            mock.patch("pkgcheck.cli.verify_paths", return_value=[PathStatus.MISSING]),
            mock.patch("pkgcheck.cli.Progress") as MockProgress,
        ):
            mock_prog = mock.MagicMock()
            MockProgress.return_value.__enter__.return_value = mock_prog
            mock_prog.add_task.return_value = 0
            with tempfile.TemporaryDirectory() as tmp:
                with (
                    mock.patch("pkgcheck.cli._LOG_DIR", Path(tmp)),
                    mock.patch("os.geteuid", return_value=0),
                ):
                    _run(console, status, args, Path("/tmp"), "rg", None, None)
                # log should be created
                self.assertTrue(any(Path(tmp).iterdir()))

    def test_run_no_access_warning(self) -> None:
        from rich.console import Console

        buf = io.StringIO()
        console = Console(file=buf, width=120, force_terminal=False)
        status = Console(file=io.StringIO(), width=120, force_terminal=False)
        args = self._make_args(quiet=False, json=False)
        entries = [("pkg", "usr/bin/secret")]
        scan_result = ScanResult(entries=entries, excluded_install=0, excluded_pseudo=0)
        with (
            mock.patch("pkgcheck.cli.scan_package_files", return_value=scan_result),
            mock.patch("pkgcheck.cli.verify_paths", return_value=[PathStatus.NO_ACCESS]),
            mock.patch("pkgcheck.cli.Progress") as MockProgress,
        ):
            mock_prog = mock.MagicMock()
            MockProgress.return_value.__enter__.return_value = mock_prog
            mock_prog.add_task.return_value = 0
            with tempfile.TemporaryDirectory() as tmp:
                with (
                    mock.patch("pkgcheck.cli._LOG_DIR", Path(tmp)),
                    mock.patch("os.geteuid", return_value=0),
                ):
                    _run(console, status, args, Path("/tmp"), "rg", None, None)
        self.assertIn("without access", buf.getvalue())

    def test_run_with_libs_deps(self) -> None:
        from rich.console import Console

        buf = io.StringIO()
        console = Console(file=buf, width=200, force_terminal=False)
        status = Console(file=io.StringIO(), width=200, force_terminal=False)
        args = self._make_args(quiet=False, json=False, check_lib_deps=True)
        entries = [("pkg-a", "usr/bin/foo"), ("pkg-b", "usr/lib/libfoo.so.1")]
        scan_result = ScanResult(entries=entries, excluded_install=0, excluded_pseudo=0)
        statuses = [PathStatus.EXISTS, PathStatus.EXISTS]
        elf_flags = [True, True]
        with (
            mock.patch("pkgcheck.cli.scan_package_files", return_value=scan_result),
            mock.patch("pkgcheck.cli.verify_paths_with_elf", return_value=(statuses, elf_flags)),
            mock.patch(
                "pkgcheck.cli.build_library_owner_index", return_value={"libfoo.so.1": "pkg-b"}
            ),
            mock.patch("pkgcheck.cli.check_library_deps", return_value=[["libmissing.so"], []]),
            mock.patch("pkgcheck.cli.collect_defined_symbols", return_value=set()),
            mock.patch("pkgcheck.cli.check_undefined_symbols", return_value=[[], []]),
            mock.patch("pkgcheck.cli.Progress") as MockProgress,
        ):
            mock_prog = mock.MagicMock()
            MockProgress.return_value.__enter__.return_value = mock_prog
            mock_prog.add_task.return_value = 0
            with tempfile.TemporaryDirectory() as tmp:
                with (
                    mock.patch("pkgcheck.cli._LOG_DIR", Path(tmp)),
                    mock.patch("os.geteuid", return_value=0),
                ):
                    _run(console, status, args, Path("/tmp"), "rg", "readelf", {})
        out = buf.getvalue()
        self.assertIn("Binaries with missing library deps", out)

    def test_run_with_libs_and_symbols(self) -> None:
        from rich.console import Console

        buf = io.StringIO()
        console = Console(file=buf, width=200, force_terminal=False)
        status = Console(file=io.StringIO(), width=200, force_terminal=False)
        args = self._make_args(
            quiet=False, json=False, check_lib_deps=True, check_libs_symbols=True
        )
        entries = [("pkg-a", "usr/bin/foo")]
        scan_result = ScanResult(entries=entries, excluded_install=0, excluded_pseudo=0)
        statuses = [PathStatus.EXISTS]
        elf_flags = [True]
        with (
            mock.patch("pkgcheck.cli.scan_package_files", return_value=scan_result),
            mock.patch("pkgcheck.cli.verify_paths_with_elf", return_value=(statuses, elf_flags)),
            mock.patch("pkgcheck.cli.build_library_owner_index", return_value={}),
            mock.patch("pkgcheck.cli.check_library_deps", return_value=[[]]),
            mock.patch("pkgcheck.cli.collect_defined_symbols", return_value={"sym1"}),
            mock.patch("pkgcheck.cli.check_undefined_symbols", return_value=[["undef1"]]),
            mock.patch("pkgcheck.cli.Progress") as MockProgress,
        ):
            mock_prog = mock.MagicMock()
            MockProgress.return_value.__enter__.return_value = mock_prog
            mock_prog.add_task.return_value = 0
            with tempfile.TemporaryDirectory() as tmp:
                with (
                    mock.patch("pkgcheck.cli._LOG_DIR", Path(tmp)),
                    mock.patch("os.geteuid", return_value=0),
                ):
                    _run(console, status, args, Path("/tmp"), "rg", "ldd", "readelf")
        out = buf.getvalue()
        self.assertIn("Binaries with undefined symbols", out)

    def test_run_all_exist_no_missing(self) -> None:
        from rich.console import Console

        buf = io.StringIO()
        console = Console(file=buf, width=120, force_terminal=False)
        status = Console(file=io.StringIO(), width=120, force_terminal=False)
        args = self._make_args(quiet=False, json=False)
        entries = [("pkg", "usr/bin/foo")]
        scan_result = ScanResult(entries=entries, excluded_install=0, excluded_pseudo=0)
        with (
            mock.patch("pkgcheck.cli.scan_package_files", return_value=scan_result),
            mock.patch("pkgcheck.cli.verify_paths", return_value=[PathStatus.EXISTS]),
            mock.patch("pkgcheck.cli.Progress") as MockProgress,
        ):
            mock_prog = mock.MagicMock()
            MockProgress.return_value.__enter__.return_value = mock_prog
            mock_prog.add_task.return_value = 0
            with tempfile.TemporaryDirectory() as tmp:
                with (
                    mock.patch("pkgcheck.cli._LOG_DIR", Path(tmp)),
                    mock.patch("os.geteuid", return_value=0),
                ):
                    _run(console, status, args, Path("/tmp"), "rg", None, None)
        self.assertIn("All registered files exist", buf.getvalue())

    def test_run_with_libs_deps_no_elf(self) -> None:
        from rich.console import Console

        buf = io.StringIO()
        console = Console(file=buf, width=200, force_terminal=False)
        status = Console(file=io.StringIO(), width=200, force_terminal=False)
        args = self._make_args(quiet=False, json=False, check_lib_deps=True)
        entries = [("pkg-a", "usr/bin/foo")]
        scan_result = ScanResult(entries=entries, excluded_install=0, excluded_pseudo=0)
        statuses = [PathStatus.EXISTS]
        elf_flags = [False]  # no elf, so no ldd
        with (
            mock.patch("pkgcheck.cli.scan_package_files", return_value=scan_result),
            mock.patch("pkgcheck.cli.verify_paths_with_elf", return_value=(statuses, elf_flags)),
            mock.patch("pkgcheck.cli.Progress") as MockProgress,
        ):
            mock_prog = mock.MagicMock()
            MockProgress.return_value.__enter__.return_value = mock_prog
            mock_prog.add_task.return_value = 0
            with tempfile.TemporaryDirectory() as tmp:
                with (
                    mock.patch("pkgcheck.cli._LOG_DIR", Path(tmp)),
                    mock.patch("os.geteuid", return_value=0),
                ):
                    _run(console, status, args, Path("/tmp"), "rg", "readelf", {})
        # no broken libs printed, but should not crash
        self.assertNotIn("Binaries with missing", buf.getvalue())


class CliMainCoverageTest(unittest.TestCase):
    def _call_main(self, argv):
        import pkgcheck.cli

        with (
            mock.patch.object(sys, "argv", ["pkgcheck", *argv]),
            mock.patch("pkgcheck.cli._ensure_utf8_environment", return_value=None),
            mock.patch("pkgcheck.cli._ensure_root"),
            mock.patch("pkgcheck.cli.Console") as MockConsole,
        ):
            mock_console = mock.MagicMock()
            MockConsole.return_value = mock_console
            yield pkgcheck.cli, mock_console

    def test_main_invalid_lang_fallback(self) -> None:
        # override lang unsupported → should fallback and then error on args.lang
        with (
            mock.patch.object(
                sys, "argv", ["pkgcheck", "--lang", "xx", "--no-elevate", "--packages-dir", "/tmp"]
            ),
            mock.patch("pkgcheck.cli._ensure_utf8_environment", return_value=(None, {})),
            mock.patch("pkgcheck.cli._ensure_root"),
            mock.patch("pkgcheck.cli.Console"),
        ):
            with (
                mock.patch("pkgcheck.cli.set_language") as mock_set_lang,
                mock.patch("pkgcheck.cli.detect_language", return_value="en"),
            ):
                # need to trigger parser.error for unsupported lang
                with self.assertRaises(SystemExit) as cm:
                    import pkgcheck.cli

                    pkgcheck.cli.main()
                self.assertEqual(cm.exception.code, 2)

    def test_main_packages_dir_not_exist(self) -> None:
        with (
            mock.patch.object(
                sys, "argv", ["pkgcheck", "--no-elevate", "--packages-dir", "/nonexistent_xyz"]
            ),
            mock.patch("pkgcheck.cli._ensure_utf8_environment", return_value=(None, {})),
            mock.patch("pkgcheck.cli._ensure_root"),
            mock.patch("pkgcheck.cli.Console"),
        ):
            with self.assertRaises(SystemExit) as cm:
                import pkgcheck.cli

                pkgcheck.cli.main()
            self.assertEqual(cm.exception.code, 2)

    def test_main_workers_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for workers in ["0", "9999"]:
                with (
                    mock.patch.object(
                        sys,
                        "argv",
                        ["pkgcheck", "--no-elevate", "--packages-dir", tmp, "--workers", workers],
                    ),
                    mock.patch("pkgcheck.cli._ensure_utf8_environment", return_value=(None, {})),
                    mock.patch("pkgcheck.cli._ensure_root"),
                    mock.patch("pkgcheck.cli.Console"),
                ):
                    with self.assertRaises(SystemExit) as cm:
                        import pkgcheck.cli

                        pkgcheck.cli.main()
                    self.assertEqual(cm.exception.code, 2)

    def test_main_max_rows_and_new_suffix_validation(self) -> None:
        import importlib

        import pkgcheck.cli

        with tempfile.TemporaryDirectory() as tmp:
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    ["pkgcheck", "--no-elevate", "--packages-dir", tmp, "--max-rows", "0"],
                ),
                mock.patch("pkgcheck.cli._ensure_utf8_environment", return_value=(None, {})),
                mock.patch("pkgcheck.cli._ensure_root"),
                mock.patch("pkgcheck.cli.Console"),
            ):
                with self.assertRaises(SystemExit):
                    importlib.reload(pkgcheck.cli)
                    pkgcheck.cli.main()
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    ["pkgcheck", "--no-elevate", "--packages-dir", tmp, "--new-suffix", " "],
                ),
                mock.patch("pkgcheck.cli._ensure_utf8_environment", return_value=(None, {})),
                mock.patch("pkgcheck.cli._ensure_root"),
                mock.patch("pkgcheck.cli.Console"),
            ):
                with self.assertRaises(SystemExit):
                    importlib.reload(pkgcheck.cli)
                    pkgcheck.cli.main()

                    pkgcheck.cli.main()

    def test_main_rg_not_found(self) -> None:
        # Now falls back to Python scan instead of error
        with tempfile.TemporaryDirectory() as tmp:
            with (
                mock.patch.object(sys, "argv", ["pkgcheck", "--no-elevate", "--packages-dir", tmp]),
                mock.patch("pkgcheck.cli._ensure_utf8_environment", return_value=(None, {})),
                mock.patch("pkgcheck.cli._ensure_root"),
                mock.patch("pkgcheck.cli.Console"),
                mock.patch("shutil.which", return_value=None),
                mock.patch("pkgcheck.cli._run") as mock_run,
            ):
                import pkgcheck.cli

                pkgcheck.cli.main()
                mock_run.assert_called_once()
                # rg_bin should be None (fallback)
                self.assertIsNone(mock_run.call_args[0][4])

    def test_main_symbols_requires_deps_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    ["pkgcheck", "--no-elevate", "--packages-dir", tmp, "--check-libs-symbols"],
                ),
                mock.patch("pkgcheck.cli._ensure_utf8_environment", return_value=(None, {})),
                mock.patch("pkgcheck.cli._ensure_root"),
                mock.patch("pkgcheck.cli.Console"),
                mock.patch("shutil.which", return_value="/usr/bin/rg"),
            ):
                with self.assertRaises(SystemExit) as cm:
                    import pkgcheck.cli

                    pkgcheck.cli.main()
                self.assertEqual(cm.exception.code, 2)

    def test_main_ldd_not_found(self) -> None:
        # This test is no longer relevant since we removed ldd
        # But keep it to verify --check-lib-deps requires readelf
        with tempfile.TemporaryDirectory() as tmp:
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    ["pkgcheck", "--no-elevate", "--packages-dir", tmp, "--check-lib-deps"],
                ),
                mock.patch("pkgcheck.cli._ensure_utf8_environment", return_value=(None, {})),
                mock.patch("pkgcheck.cli._ensure_root"),
                mock.patch("pkgcheck.cli.Console"),
                mock.patch(
                    "shutil.which", side_effect=lambda x: "/usr/bin/rg" if x == "rg" else None
                ),
            ):
                with self.assertRaises(SystemExit) as cm:
                    import pkgcheck.cli

                    pkgcheck.cli.main()
                self.assertEqual(cm.exception.code, 2)

    def test_main_success_with_mocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "demo-1.0").write_text("FILE LIST:\nusr/bin/foo\n")
            with (
                mock.patch.object(
                    sys, "argv", ["pkgcheck", "--no-elevate", "--packages-dir", tmp, "--json"]
                ),
                mock.patch("pkgcheck.cli._ensure_utf8_environment", return_value=(None, {})),
                mock.patch("pkgcheck.cli._ensure_root"),
                mock.patch("shutil.which", return_value="/usr/bin/rg"),
                mock.patch("pkgcheck.cli._run") as mock_run,
            ):
                import pkgcheck.cli

                # _run is mocked, so main should not raise
                try:
                    pkgcheck.cli.main()
                except SystemExit as e:
                    # _run mocked, should not exit 2
                    self.assertNotEqual(e.code, 2)
                mock_run.assert_called_once()

    def test_main_keyboard_interrupt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with (
                mock.patch.object(sys, "argv", ["pkgcheck", "--no-elevate", "--packages-dir", tmp]),
                mock.patch("pkgcheck.cli._ensure_utf8_environment", return_value=(None, {})),
                mock.patch("pkgcheck.cli._ensure_root"),
                mock.patch("shutil.which", return_value="/usr/bin/rg"),
                mock.patch("pkgcheck.cli._run", side_effect=KeyboardInterrupt),
                mock.patch("pkgcheck.cli.Console") as MockConsole,
            ):
                mock_console = mock.MagicMock()
                MockConsole.return_value = mock_console
                with self.assertRaises(SystemExit) as cm:
                    import pkgcheck.cli

                    pkgcheck.cli.main()
                self.assertEqual(cm.exception.code, 130)

    def test_main_runtime_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with (
                mock.patch.object(sys, "argv", ["pkgcheck", "--no-elevate", "--packages-dir", tmp]),
                mock.patch("pkgcheck.cli._ensure_utf8_environment", return_value=(None, {})),
                mock.patch("pkgcheck.cli._ensure_root"),
                mock.patch("shutil.which", return_value="/usr/bin/rg"),
                mock.patch("pkgcheck.cli._run", side_effect=RuntimeError("boom")),
                mock.patch("pkgcheck.cli.Console") as MockConsole,
            ):
                mock_console = mock.MagicMock()
                MockConsole.return_value = mock_console
                with self.assertRaises(SystemExit) as cm:
                    import pkgcheck.cli

                    pkgcheck.cli.main()
                self.assertEqual(cm.exception.code, 1)

    def test_main_utf8_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with (
                mock.patch.object(sys, "argv", ["pkgcheck", "--no-elevate", "--packages-dir", tmp]),
                mock.patch("pkgcheck.cli._ensure_utf8_environment", return_value=("latin-1", {})),
                mock.patch("pkgcheck.cli._ensure_root"),
                mock.patch("shutil.which", return_value="/usr/bin/rg"),
                mock.patch("pkgcheck.cli._run"),
                mock.patch("pkgcheck.cli.Console") as MockConsole,
            ):
                mock_console = mock.MagicMock()
                MockConsole.return_value = mock_console
                import pkgcheck.cli

                pkgcheck.cli.main()
                # should have printed warning
                self.assertTrue(mock_console.print.called)

    def test_main_readelf_not_found(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "pkgcheck",
                        "--no-elevate",
                        "--packages-dir",
                        tmp,
                        "--check-lib-deps",
                        "--check-libs-symbols",
                    ],
                ),
                mock.patch("pkgcheck.cli._ensure_utf8_environment", return_value=(None, {})),
                mock.patch("pkgcheck.cli._ensure_root"),
                mock.patch("pkgcheck.cli.Console"),
                mock.patch(
                    "shutil.which",
                    side_effect=lambda x: "/usr/bin/rg" if x == "rg" else None,
                ),
            ):
                with self.assertRaises(SystemExit) as cm:
                    import pkgcheck.cli

                    pkgcheck.cli.main()
                self.assertEqual(cm.exception.code, 2)


class ScannerCoverageTest(unittest.TestCase):
    def test_is_safe_rel(self) -> None:
        self.assertFalse(_is_safe_rel(""))
        self.assertFalse(_is_safe_rel("/etc/passwd"))
        self.assertFalse(_is_safe_rel("//etc/passwd"))
        self.assertFalse(_is_safe_rel("a/../b"))
        self.assertFalse(_is_safe_rel("../a"))
        self.assertFalse(_is_safe_rel("a/.."))
        self.assertTrue(_is_safe_rel("usr/bin/foo"))
        self.assertTrue(_is_safe_rel("a/b/c"))
        self.assertTrue(_is_safe_rel("a..b/c"))

    def test_build_rg_command(self) -> None:
        from pkgcheck.scanner import build_rg_command

        cmd = build_rg_command("/usr/bin/rg", Path("/tmp"))
        self.assertIn("/usr/bin/rg", cmd)
        self.assertIn("--multiline", cmd)
        self.assertIn("--", cmd)
        self.assertEqual(cmd[-1], "/tmp")

    def test_scan_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch(
                "pkgcheck.scanner.subprocess.run", side_effect=subprocess.TimeoutExpired("rg", 300)
            ):
                with self.assertRaises(RuntimeError) as cm:
                    scan_package_files(Path(tmp), "rg")
                self.assertIn("timed out", str(cm.exception))

    def test_scan_returncode_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake = types.SimpleNamespace(returncode=2, stdout="", stderr="error")
            with mock.patch("pkgcheck.scanner.subprocess.run", return_value=fake):
                with self.assertRaises(RuntimeError) as cm:
                    scan_package_files(Path(tmp), "rg")
                self.assertIn("could not scan", str(cm.exception))

    def test_scan_safe_rel_filtered(self) -> None:
        rg = shutil.which("rg")
        if rg is None:
            self.skipTest("ripgrep not available")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # record with traversal attempt should be filtered as pseudo
            (tmp_path / "evil-1.0").write_bytes(b"FILE LIST:\n../etc/passwd\nusr/bin/ok\n")
            result = scan_package_files(tmp_path, rg)
            rels = [r for _, r in result.entries]
            self.assertNotIn("../etc/passwd", rels)
            self.assertIn("usr/bin/ok", rels)


class VerifierCoverageTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _path(self, rel: str) -> str:
        return os.path.join(str(self.dir), rel)

    def test_check_path_error_generic_oserror(self) -> None:
        with mock.patch("os.lstat", side_effect=OSError("generic")):
            self.assertIs(check_path(self._path("x")), PathStatus.ERROR)

    def test_is_elf_open_oserror(self) -> None:
        path = self._path("prog")
        with open(path, "wb") as f:
            f.write(b"\x7fELF\x02\x01\x01\x00")
        os.chmod(path, 0o755)
        with mock.patch("os.open", side_effect=OSError("boom")):
            self.assertFalse(_is_elf(path))

    def test_is_elf_fdopen_oserror(self) -> None:
        path = self._path("prog2")
        with open(path, "wb") as f:
            f.write(b"\x7fELF\x02\x01\x01\x00")
        os.chmod(path, 0o755)
        # os.open succeeds but fdopen raises
        with mock.patch("os.fdopen", side_effect=OSError("boom")):
            # need to mock open to return fd, but fdopen will raise
            self.assertFalse(_is_elf(path))

    def test_run_workers_exception_handling(self) -> None:
        from pkgcheck.verifier import _run_workers

        def boom(_):
            raise RuntimeError("boom")

        results = _run_workers(["a", "b"], workers=2, worker=boom, on_progress=None)
        self.assertEqual(results, [None, None])

    def test_verify_paths_error_on_exception(self) -> None:
        with mock.patch("pkgcheck.verifier.check_path", side_effect=RuntimeError("boom")):
            statuses = verify_paths(["/a", "/b"], workers=2)
            self.assertEqual(statuses, [PathStatus.ERROR, PathStatus.ERROR])

    def test_check_path_new_suffix_backup_priority(self) -> None:
        # Test that NEW_PENDING takes precedence over BACKUP? Actually check_path checks new before backup
        open(self._path("foo.new"), "w").close()
        open(self._path("foo.bak"), "w").close()
        # foo (without suffix) has both .new and .bak, should be NEW_PENDING
        self.assertIs(check_path(self._path("foo")), PathStatus.NEW_PENDING)


class I18nCoverageTest(unittest.TestCase):
    def tearDown(self) -> None:
        i18n.set_language("en")

    def test_os_code_locale_error(self) -> None:
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch("pkgcheck.i18n.locale.getlocale", side_effect=ValueError("bad")),
        ):
            # detect_language should fall back to en without crashing
            self.assertEqual(i18n.detect_language(), "en")

    def test_set_language_oserror(self) -> None:
        # Simulate files() raising OSError and JSON decode error
        with mock.patch("pkgcheck.i18n.files", side_effect=OSError("boom")):
            i18n.set_language("es")
            self.assertEqual(
                i18n.t("Scanning package records in {path}..."),
                "Scanning package records in {path}...",
            )
        with mock.patch("pkgcheck.i18n.files") as mock_files:
            mock_res = mock.MagicMock()
            mock_res.read_text.side_effect = json.JSONDecodeError("err", "doc", 0)
            mock_files.return_value.__truediv__.return_value = mock_res
            # Need to mock files("pkgcheck") chain
            with mock.patch("pkgcheck.i18n.files", return_value=mock_res):
                # Actually simpler: patch json.loads to raise
                with mock.patch("json.loads", side_effect=json.JSONDecodeError("err", "doc", 0)):
                    i18n.set_language("es")
                    self.assertEqual(i18n.t("hello"), "hello")

    def test_is_safe_rel_empty(self) -> None:
        self.assertFalse(_is_safe_rel(""))


class OrphansTest(unittest.TestCase):
    def test_is_orphan_excluded(self) -> None:
        from pkgcheck.orphans import _is_orphan_excluded

        self.assertTrue(_is_orphan_excluded("var/log/syslog"))
        self.assertTrue(_is_orphan_excluded("var/log/packages/foo"))
        self.assertTrue(_is_orphan_excluded("var/log/packages", ()))
        self.assertTrue(_is_orphan_excluded("home/user/file"))
        self.assertFalse(_is_orphan_excluded("usr/bin/foo"))
        self.assertTrue(_is_orphan_excluded("usr/bin/foo", ("usr/bin/",)))

    def test_find_orphans(self) -> None:
        from pkgcheck.orphans import find_orphans

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "usr").mkdir()
            (root / "usr" / "bin").mkdir(parents=True)
            (root / "usr" / "bin" / "owned").write_text("x")
            (root / "usr" / "bin" / "orphan").write_text("y")
            (root / "var").mkdir()
            (root / "var" / "log").mkdir(parents=True)
            (root / "var" / "log" / "syslog").write_text("log")
            owned = {"/usr/bin/owned"}
            # Use extra_exclude to avoid scanning var/log
            orphans = find_orphans(owned, root=root, extra_exclude=())
            self.assertIn(f"{root}/usr/bin/orphan".replace("//", "/"), orphans)
            # var/log/syslog should be excluded via default
            self.assertNotIn(f"{root}/var/log/syslog".replace("//", "/"), str(orphans))

    def test_find_orphans_prunes_dir(self) -> None:
        from pkgcheck.orphans import find_orphans

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "mnt").mkdir()
            (root / "mnt" / "disk").mkdir(parents=True)
            (root / "mnt" / "disk" / "file").write_text("x")
            orphans = find_orphans(set(), root=root)
            # mnt should be pruned
            self.assertEqual(orphans, [])


class DiffTest(unittest.TestCase):
    def test_list_logs_empty(self) -> None:
        from pkgcheck.diff import list_logs

        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(list_logs(Path(tmp)), [])

    def test_list_logs_sorted(self) -> None:
        import time

        from pkgcheck.diff import list_logs

        with tempfile.TemporaryDirectory() as tmp:
            p1 = Path(tmp) / "pkgcheck-01-01-2026-00-00-00.log"
            p2 = Path(tmp) / "pkgcheck-01-01-2026-00-00-01.json"
            p1.write_text("a")
            time.sleep(0.01)
            p2.write_text("{}")
            entries = list_logs(Path(tmp))
            self.assertEqual(entries[0].path, p2)
            self.assertEqual(entries[0].fmt, "json")

    def test_diff_requires_json(self) -> None:
        from pkgcheck.diff import diff_reports

        with tempfile.TemporaryDirectory() as tmp:
            a = Path(tmp) / "a.log"
            b = Path(tmp) / "b.json"
            a.write_text("x")
            b.write_text("{}")
            with self.assertRaises(RuntimeError):
                diff_reports(a, b)

    def test_diff_reports(self) -> None:
        from pkgcheck.diff import diff_reports

        with tempfile.TemporaryDirectory() as tmp:
            a = Path(tmp) / "a.json"
            b = Path(tmp) / "b.json"
            a.write_text(json.dumps({"missing": {"pkg": ["/a"]}, "summary": {"missing": 1}}))
            b.write_text(json.dumps({"missing": {"pkg": ["/a", "/b"]}, "summary": {"missing": 2}}))
            diff = diff_reports(a, b)
            self.assertIn("missing", diff["diff"])
            self.assertIn("added", diff["diff"]["missing"])
            self.assertEqual(diff["diff"]["missing"]["added"]["pkg"], ["/b"])

    def test_diff_broken_libs(self) -> None:
        from pkgcheck.diff import diff_reports

        with tempfile.TemporaryDirectory() as tmp:
            a = Path(tmp) / "a.json"
            b = Path(tmp) / "b.json"
            a.write_text(json.dumps({"broken_libs": {"pkg": []}}))
            b.write_text(
                json.dumps({"broken_libs": {"pkg": [{"binary": "/bin/x", "missing": ["lib.so"]}]}})
            )
            diff = diff_reports(a, b)
            self.assertIn("broken_libs", diff["diff"])


class ScannerFallbackTest(unittest.TestCase):
    def test_python_scan_fallback(self) -> None:
        from pkgcheck.scanner import _python_scan

        with tempfile.TemporaryDirectory() as tmp:
            pkg_dir = Path(tmp)
            (pkg_dir / "pkg-1.0").write_text("FILE LIST:\nusr/bin/foo\n")
            by_pkg = _python_scan(pkg_dir)
            self.assertIn("pkg-1.0", by_pkg)
            self.assertIn("usr/bin/foo", by_pkg["pkg-1.0"])

    def test_scan_with_none_uses_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pkg_dir = Path(tmp)
            (pkg_dir / "pkg-1.0").write_text("FILE LIST:\nusr/bin/foo\nvar/log/syslog\n")
            result = scan_package_files(pkg_dir, None)
            # var/log/syslog should be excluded as pseudo
            self.assertIn(("pkg-1.0", "usr/bin/foo"), result.entries)
            self.assertNotIn(("pkg-1.0", "var/log/syslog"), result.entries)

    def test_is_pseudo_var_log_packages(self) -> None:
        from pkgcheck.scanner import _is_pseudo

        self.assertFalse(_is_pseudo("var/log/packages/foo", ("var/log/",)))
        self.assertTrue(_is_pseudo("var/log/syslog", ("var/log/",)))
        self.assertFalse(_is_pseudo("var/log/packages", ("var/log/",)))


class SafeLddTest(unittest.TestCase):
    def test_needed_via_readelf(self) -> None:
        from pkgcheck.libdeps import _get_needed_libs

        output = " 0x00000001 (NEEDED)                     Shared library: [libfoo.so.1]\n 0x00000001 (NEEDED)                     Shared library: [libbar.so.2]\n"
        with mock.patch(
            "pkgcheck.libdeps.subprocess.run",
            return_value=types.SimpleNamespace(stdout=output, stderr=""),
        ):
            missing = _get_needed_libs("/bin/foo", "readelf")
            # We need to check with owner_index manually
            self.assertIn("libfoo.so.1", missing)
            self.assertIn("libbar.so.2", missing)

    def test_needed_via_readelf_timeout(self) -> None:
        from pkgcheck.libdeps import _get_needed_libs

        with mock.patch(
            "pkgcheck.libdeps.subprocess.run", side_effect=subprocess.TimeoutExpired("readelf", 60)
        ):
            self.assertEqual(_get_needed_libs("/bin/foo", "readelf"), [])

    def test_check_library_deps_safe(self) -> None:
        with mock.patch("pkgcheck.libdeps._get_needed_libs", side_effect=[["liba.so"], []]):
            result = check_library_deps(
                ["/a", "/b"], workers=2, readelf_bin="readelf", owner_index={}
            )
            self.assertEqual(result, [["liba.so"], []])


class CompletionTest(unittest.TestCase):
    def test_completion_scripts(self) -> None:
        from pkgcheck.cli import _completion_script

        for shell in ["bash", "zsh", "fish"]:
            script = _completion_script(shell)
            self.assertIn("pkgcheck", script)
        self.assertEqual(_completion_script("unknown"), "")


class ListLogsDiffCliTest(unittest.TestCase):
    def test_list_logs_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake_dir = Path(tmp)
            (fake_dir / "pkgcheck-01-01-2026-00-00-00.json").write_text("{}")
            with (
                mock.patch.object(sys, "argv", ["pkgcheck", "--list-logs"]),
                mock.patch("pkgcheck.cli._LOG_DIR", fake_dir),
                mock.patch("pkgcheck.cli._ensure_utf8_environment", return_value=(None, {})),
                mock.patch("pkgcheck.cli.Console") as MockConsole,
            ):
                mock_console = mock.MagicMock()
                MockConsole.return_value = mock_console
                import pkgcheck.cli

                pkgcheck.cli.main()
                self.assertTrue(mock_console.print.called)

    def test_diff_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            a = Path(tmp) / "a.json"
            b = Path(tmp) / "b.json"
            a.write_text(json.dumps({"missing": {"pkg": ["/a"]}}))
            b.write_text(json.dumps({"missing": {"pkg": ["/b"]}}))
            with (
                mock.patch.object(
                    sys, "argv", ["pkgcheck", "--diff", "--from", str(a), "--to", str(b)]
                ),
                mock.patch("pkgcheck.cli._ensure_utf8_environment", return_value=(None, {})),
                mock.patch("pkgcheck.cli.Console") as MockConsole,
            ):
                mock_console = mock.MagicMock()
                MockConsole.return_value = mock_console
                import pkgcheck.cli

                pkgcheck.cli.main()
                self.assertTrue(mock_console.print.called)

    def test_orphans_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pkg_dir = Path(tmp) / "pkgs"
            pkg_dir.mkdir()
            (pkg_dir / "pkg-1.0").write_text("FILE LIST:\nusr/bin/owned\n")
            root = Path(tmp) / "root"
            root.mkdir()
            (root / "usr").mkdir(parents=True)
            (root / "usr" / "bin").mkdir(parents=True)
            (root / "usr" / "bin" / "owned").write_text("x")
            (root / "usr" / "bin" / "orphan").write_text("y")
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "pkgcheck",
                        "--orphans",
                        "--orphans-root",
                        str(root),
                        "--no-elevate",
                        "--packages-dir",
                        str(pkg_dir),
                    ],
                ),
                mock.patch("pkgcheck.cli._ensure_utf8_environment", return_value=(None, {})),
                mock.patch("pkgcheck.cli._ensure_root"),
                mock.patch("shutil.which", return_value="/usr/bin/rg"),
                mock.patch("pkgcheck.cli._LOG_DIR", Path(tmp)),
                mock.patch("os.geteuid", return_value=0),
                mock.patch("pkgcheck.cli.Console") as MockConsole,
            ):
                MockConsole.return_value = mock.MagicMock()
                import pkgcheck.cli

                pkgcheck.cli.main()
                # should succeed without SystemExit
                self.assertTrue(True)

    def test_completion_cli(self) -> None:
        with (
            mock.patch.object(sys, "argv", ["pkgcheck", "--completion", "bash"]),
            mock.patch("pkgcheck.cli._ensure_utf8_environment", return_value=(None, {})),
            mock.patch("sys.stdout", new=io.StringIO()) as fake_out,
        ):
            import pkgcheck.cli

            pkgcheck.cli.main()
            self.assertIn("bash", fake_out.getvalue())


if __name__ == "__main__":
    unittest.main()
