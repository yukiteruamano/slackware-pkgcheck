"""Extra coverage tests to reach 85% threshold — unit test mocking."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pkgcheck.validate import (
    ValidationError,
    _contains_control_chars,
    _contains_forbidden_chars,
    sanitize_for_subprocess,
    validate_backup_suffixes,
    validate_binary_path,
    validate_exclude_prefix,
    validate_new_suffix,
    validate_orphans_root,
    validate_packages_dir,
    validate_safe_path,
    validate_subprocess_arg,
    validate_suffix,
)


class ValidateSafePathTest(unittest.TestCase):
    def test_not_string(self) -> None:
        with self.assertRaises(ValidationError):
            validate_safe_path(123)

    def test_empty(self) -> None:
        with self.assertRaises(ValidationError):
            validate_safe_path("")

    def test_too_long(self) -> None:
        with self.assertRaises(ValidationError):
            validate_safe_path("a" * 5000)

    def test_forbidden_chars(self) -> None:
        with self.assertRaises(ValidationError):
            validate_safe_path("a\x00b")

    def test_control_chars(self) -> None:
        with self.assertRaises(ValidationError):
            validate_safe_path("a\x01b")

    def test_normpath_exception(self) -> None:
        with mock.patch("os.path.normpath", side_effect=RuntimeError("boom")):
            with self.assertRaises(ValidationError):
                validate_safe_path("a/b")

    def test_absolute_not_allowed(self) -> None:
        with self.assertRaises(ValidationError):
            validate_safe_path("/etc/passwd", allow_absolute=False)

    def test_absolute_allowed(self) -> None:
        # should not raise
        self.assertEqual(validate_safe_path("/etc/passwd", allow_absolute=True), "/etc/passwd")

    def test_traversal_no_base(self) -> None:
        with self.assertRaises(ValidationError):
            validate_safe_path("a/../../b")

    def test_traversal_with_base_ok(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "sub").mkdir()
            path = str(base / "sub" / ".." / "sub" / "file")
            # resolve will be inside base
            result = validate_safe_path(path, allow_absolute=True, base_dir=str(base))
            self.assertIn("file", result)

    def test_traversal_with_base_escape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "sub").mkdir()
            other = tempfile.mkdtemp()
            try:
                path = str(Path(other) / "file")
                Path(path).touch()
                with self.assertRaises(ValidationError):
                    validate_safe_path(path, allow_absolute=True, base_dir=str(base))
            finally:
                os.unlink(path)
                os.rmdir(other)

    def test_traversal_resolve_exception(self) -> None:
        with mock.patch("pathlib.Path.resolve", side_effect=OSError("boom")):
            with self.assertRaises(ValidationError):
                validate_safe_path("a/../b", base_dir="/tmp")

    def test_must_exist_ok(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "file"
            p.touch()
            self.assertEqual(
                validate_safe_path(str(p), allow_absolute=True, must_exist=True), str(p)
            )

    def test_must_exist_broken_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            link = Path(tmp) / "link"
            link.symlink_to("/nonexistent/target")
            # lexists true, so should pass
            self.assertEqual(
                validate_safe_path(str(link), allow_absolute=True, must_exist=True), str(link)
            )

    def test_must_exist_missing(self) -> None:
        with self.assertRaises(ValidationError):
            validate_safe_path("/nonexistent_xyz_12345", allow_absolute=True, must_exist=True)

    def test_contains_helpers(self) -> None:
        self.assertTrue(_contains_forbidden_chars("\x00"))
        self.assertFalse(_contains_forbidden_chars("abc"))
        self.assertTrue(_contains_control_chars("\x01"))
        self.assertFalse(_contains_control_chars("abc"))


class ValidateSubprocessArgTest(unittest.TestCase):
    def test_not_string(self) -> None:
        with self.assertRaises(ValidationError):
            validate_subprocess_arg(123)

    def test_empty(self) -> None:
        with self.assertRaises(ValidationError):
            validate_subprocess_arg("")

    def test_too_long(self) -> None:
        with self.assertRaises(ValidationError):
            validate_subprocess_arg("a" * 9000)

    def test_forbidden(self) -> None:
        with self.assertRaises(ValidationError):
            validate_subprocess_arg("a\nb")

    def test_control(self) -> None:
        with self.assertRaises(ValidationError):
            validate_subprocess_arg("a\x01b")

    def test_shell_metachars_allowed(self) -> None:
        # should not raise — we pass
        self.assertEqual(validate_subprocess_arg("a|b"), "a|b")
        self.assertEqual(validate_subprocess_arg("a&b"), "a&b")

    def test_ok(self) -> None:
        self.assertEqual(validate_subprocess_arg("hello"), "hello")


class ValidateExcludePrefixTest(unittest.TestCase):
    def test_not_string(self) -> None:
        with self.assertRaises(ValidationError):
            validate_exclude_prefix(123)

    def test_empty(self) -> None:
        with self.assertRaises(ValidationError):
            validate_exclude_prefix("")

    def test_only_slashes(self) -> None:
        with self.assertRaises(ValidationError):
            validate_exclude_prefix("///")

    def test_forbidden(self) -> None:
        with self.assertRaises(ValidationError):
            validate_exclude_prefix("a\x00/b/")

    def test_control(self) -> None:
        with self.assertRaises(ValidationError):
            validate_exclude_prefix("a\x01/b/")

    def test_traversal(self) -> None:
        with self.assertRaises(ValidationError):
            validate_exclude_prefix("a/../b")

    def test_add_trailing_slash(self) -> None:
        self.assertEqual(validate_exclude_prefix("mnt"), "mnt/")
        self.assertEqual(validate_exclude_prefix("/mnt"), "mnt/")
        self.assertEqual(validate_exclude_prefix("mnt/"), "mnt/")


class ValidateSuffixTest(unittest.TestCase):
    def test_not_string(self) -> None:
        with self.assertRaises(ValidationError):
            validate_suffix(123)

    def test_empty_not_allowed(self) -> None:
        with self.assertRaises(ValidationError):
            validate_suffix("")

    def test_empty_allowed(self) -> None:
        self.assertEqual(validate_suffix("", allow_empty=True), "")

    def test_too_long(self) -> None:
        with self.assertRaises(ValidationError):
            validate_suffix("a" * 70)

    def test_forbidden(self) -> None:
        with self.assertRaises(ValidationError):
            validate_suffix("a\x00")

    def test_control(self) -> None:
        with self.assertRaises(ValidationError):
            validate_suffix("a\x01")

    def test_add_dot(self) -> None:
        self.assertEqual(validate_suffix("bak"), ".bak")
        self.assertEqual(validate_suffix(".bak"), ".bak")

    def test_strip(self) -> None:
        self.assertEqual(validate_suffix(" .bak "), ".bak")


class ValidateBackupSuffixesTest(unittest.TestCase):
    def test_not_string(self) -> None:
        with self.assertRaises(ValidationError):
            validate_backup_suffixes(123)

    def test_empty_csv(self) -> None:
        with self.assertRaises(ValidationError):
            validate_backup_suffixes("")

    def test_only_commas(self) -> None:
        with self.assertRaises(ValidationError):
            validate_backup_suffixes(" , , ")

    def test_dedup(self) -> None:
        self.assertEqual(validate_backup_suffixes(".bak,.bak,.orig"), (".bak", ".orig"))

    def test_invalid_suffix_in_csv(self) -> None:
        with self.assertRaises(ValidationError):
            validate_backup_suffixes(".bak, \x00")

    def test_single(self) -> None:
        self.assertEqual(validate_backup_suffixes(".bak"), (".bak",))


class SanitizeTest(unittest.TestCase):
    def test_not_string(self) -> None:
        self.assertEqual(sanitize_for_subprocess(123), "123")  # type: ignore

    def test_newline_replace(self) -> None:
        self.assertEqual(sanitize_for_subprocess("a\nb"), "a b")
        self.assertEqual(sanitize_for_subprocess("a\rb"), "a b")
        self.assertEqual(sanitize_for_subprocess("a\tb"), "a b")

    def test_control_drop(self) -> None:
        self.assertEqual(sanitize_for_subprocess("a\x01b"), "ab")
        self.assertEqual(sanitize_for_subprocess("a\x7fb"), "ab")

    def test_normal(self) -> None:
        self.assertEqual(sanitize_for_subprocess("hello"), "hello")


class ValidateBinaryPathTest(unittest.TestCase):
    def test_not_string(self) -> None:
        with self.assertRaises(ValidationError):
            validate_binary_path(123)

    def test_empty(self) -> None:
        with self.assertRaises(ValidationError):
            validate_binary_path("")

    def test_absolute_ok(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"x")
            tf.flush()
            name = tf.name
        try:
            self.assertEqual(validate_binary_path(name), name)
        finally:
            os.unlink(name)

    def test_simple_invalid(self) -> None:
        with self.assertRaises(ValidationError):
            validate_binary_path("bad;name")

    def test_simple_ok(self) -> None:
        self.assertEqual(validate_binary_path("ldd"), "ldd")


class ValidatePackagesOrphansTest(unittest.TestCase):
    def test_packages_ok(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(validate_packages_dir(tmp), tmp)

    def test_orphans_ok(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(validate_orphans_root(tmp), tmp)

    def test_validate_new_suffix_ok(self) -> None:
        self.assertEqual(validate_new_suffix(".new"), ".new")
