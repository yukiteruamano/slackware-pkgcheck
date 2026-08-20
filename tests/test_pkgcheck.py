"""Test suite for pkgcheck (stdlib unittest, no external dependencies)."""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import tempfile
import types
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

from pkgcheck import i18n
from pkgcheck.cli import (
    _backup_suffixes,
    _ensure_utf8_environment,
    _is_utf8,
    _new_suffix,
    _pseudo_prefixes,
)
from pkgcheck.libdeps import (
    _missing_libs_of,
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
)
from pkgcheck.scanner import scan_package_files
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

    def test_missing_libs_parses_not_found(self) -> None:
        output = (
            "linux-vdso.so.1 (0x00007fff)\n"
            "libc.so.6 => /lib64/libc.so.6 (0x00007f)\n"
            "libfoo.so.1 => not found\n"
            "libbar.so.2 => not found\n"
        )
        with mock.patch(
            "pkgcheck.libdeps.subprocess.run",
            return_value=self._fake_run(output),
        ) as run:
            missing = _missing_libs_of("/x", "ldd")
        self.assertEqual(missing, ["libfoo.so.1", "libbar.so.2"])
        run.assert_called_once()

    def test_missing_libs_ignores_not_dynamic(self) -> None:
        with mock.patch(
            "pkgcheck.libdeps.subprocess.run",
            return_value=self._fake_run("not a dynamic executable\n"),
        ):
            self.assertEqual(_missing_libs_of("/x", "ldd"), [])

    def test_check_library_deps_preserves_order_and_progress(self) -> None:
        with mock.patch("pkgcheck.libdeps._missing_libs_of", side_effect=[["a"], [], ["b"]]) as m:
            events: list[int] = []
            result = check_library_deps(["/x", "/y", "/z"], 3, "ldd", on_progress=events.append)
        self.assertEqual(result, [["a"], [], ["b"]])
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

    def test_missing_libs_timeout_returns_empty(self) -> None:
        with mock.patch(
            "pkgcheck.libdeps.subprocess.run", side_effect=subprocess.TimeoutExpired("ldd", 60)
        ):
            self.assertEqual(_missing_libs_of("/x", "ldd"), [])

    def test_missing_libs_oserror_returns_empty(self) -> None:
        with mock.patch("pkgcheck.libdeps.subprocess.run", side_effect=OSError("boom")):
            self.assertEqual(_missing_libs_of("/x", "ldd"), [])

    def test_missing_libs_malformed_output(self) -> None:
        output = (
            "garbage line\n"
            "libfoo.so.1 => not found\n"
            "stray text not found\n"
            "libbar.so.2 => not found (0x00007f)\n"
        )
        with mock.patch("pkgcheck.libdeps.subprocess.run", return_value=self._fake_run(output)):
            missing = _missing_libs_of("/x", "ldd")
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
        self.assertEqual(check_library_deps([], 4, "ldd"), [])


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
            self.assertIsNone(_ensure_utf8_environment())
            self.assertNotIn("PYTHONIOENCODING", os.environ)

    def test_ensure_utf8_environment_forces_fallback(self) -> None:
        with (
            mock.patch("sys.stdout", _FakeStream("ISO-8859-1")),
            mock.patch("sys.stderr", _FakeStream("latin-1")),
            mock.patch.dict(os.environ, {}, clear=True),
        ):
            previous = _ensure_utf8_environment()
            self.assertEqual(previous, "ISO-8859-1")
            self.assertEqual(os.environ["PYTHONIOENCODING"], "utf-8")
            self.assertEqual(os.environ["LANG"], "en_US.UTF-8")
            self.assertEqual(os.environ["LC_ALL"], "en_US.UTF-8")

    def test_ensure_utf8_environment_survives_reconfigure_failure(self) -> None:
        class _NoReconfigure(_FakeStream):
            def reconfigure(self, **_):
                raise AttributeError("not a text stream")

        with (
            mock.patch("sys.stdout", _NoReconfigure("latin-1")),
            mock.patch("sys.stderr", _FakeStream("UTF-8")),
            mock.patch.dict(os.environ, {}, clear=True),
        ):
            previous = _ensure_utf8_environment()
            self.assertEqual(previous, "latin-1")
            self.assertEqual(os.environ["PYTHONIOENCODING"], "utf-8")


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
        self.assertIn("--check-libs-deps", result.stderr)

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
                "--packages-dir", tmp, "--check-libs-deps", "--no-elevate", "--lang", "en", env=env
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


if __name__ == "__main__":
    unittest.main()
