"""Lightweight internationalization for pkgcheck.

English is the base language: the strings in the code act as keys and are translated by
looking them up in ``locales/{lang}.json``. If there is no translation, the original
(identity) is returned. The language is detected from the operating system and can be
forced with ``--lang`` or the ``PKGCHECK_LANG`` environment variable.
"""

from __future__ import annotations

import json
import locale
import os
from importlib.resources import files
from typing import Final

DEFAULT_LANGUAGE = "en"

SUPPORTED_LANGUAGES: Final = ("es", "pt", "fr", "de", "zh", "ja")
ALL_LANGUAGES: Final = (DEFAULT_LANGUAGE, *SUPPORTED_LANGUAGES)

_LOCALE_ENV_KEYS = ("LC_ALL", "LC_MESSAGES", "LANG")

# Markers of Traditional Chinese (we have no zh-Hant translation): use the fallback.
_TRADITIONAL_ZH_MARKERS = ("_TW", "_HK", "_MO", "_HANT", "-TW", "-HK", "-MO", "-HANT")

_table: dict[str, str] = {}
_current = DEFAULT_LANGUAGE


def _normalize(value: str) -> str:
    """Reduces a locale (``es_ES.UTF-8``, ``pt-BR``...) to a 2-letter code."""
    return value.split(".", 1)[0].split("_", 1)[0].split("-", 1)[0].strip().lower()


def _is_traditional_zh(code: str) -> bool:
    """Returns whether `code` refers to Traditional Chinese (zh-Hant)."""
    upper = code.upper()
    return any(marker in upper for marker in _TRADITIONAL_ZH_MARKERS)


def _validate(code: str) -> str:
    """Returns the language for `code`; falls back to the default if unsupported."""
    normalized = _normalize(code)
    if normalized in SUPPORTED_LANGUAGES:
        if normalized == "zh" and _is_traditional_zh(code):
            return DEFAULT_LANGUAGE
        return normalized
    return DEFAULT_LANGUAGE


def is_supported(code: str) -> bool:
    """Returns whether `code` maps to a language we can actually display."""
    normalized = _normalize(code)
    if normalized == DEFAULT_LANGUAGE:
        return True
    return _validate(code) != DEFAULT_LANGUAGE


def _os_code() -> str | None:
    """Detects the OS locale code (e.g. ``es_ES``) from the environment."""
    for key in _LOCALE_ENV_KEYS:
        value = os.environ.get(key)
        if value:
            if value in ("C", "POSIX", "C.UTF-8"):
                return None
            return value.split(".", 1)[0]
    try:
        code, _ = locale.getlocale()
    except (ValueError, locale.Error):
        return None
    return code


def detect_language(override: str | None = None) -> str:
    """Determines the active language.

    Precedence: ``--lang`` > ``PKGCHECK_LANG`` > OS locale > ``DEFAULT_LANGUAGE``.
    """
    if override:
        return _validate(override)
    env = os.environ.get("PKGCHECK_LANG")
    if env:
        return _validate(env)
    code = _os_code()
    if code:
        return _validate(code)
    return DEFAULT_LANGUAGE


def set_language(lang: str) -> None:
    """Loads the translations for `lang`; English (default) needs no file."""
    global _table, _current
    _current = _validate(lang)
    _table = {}
    if _current == DEFAULT_LANGUAGE:
        return
    try:
        resource = files("pkgcheck") / "locales" / f"{_current}.json"
        _table = json.loads(resource.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        _table = {}


def t(message: str) -> str:
    """Translates `message` according to the active language; identity if untranslated."""
    return _table.get(message, message)
