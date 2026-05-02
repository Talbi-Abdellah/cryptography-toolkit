"""CLI input/output helpers."""
import os
import sys
from pathlib import Path
from typing import Any, Callable, List, Optional, TypeVar

from utils.display import Display

T = TypeVar("T")


def prompt(text: str, default: str = "") -> str:
    """Show a styled prompt and return stripped input."""
    suffix = f" [{default}]" if default else ""
    try:
        val = input(f"  → {text}{suffix}: ").strip()
        return val if val else default
    except (EOFError, KeyboardInterrupt):
        return default


def prompt_int(text: str, min_val: int, max_val: int, default: int) -> int:
    """Prompt for an integer in [min_val, max_val]."""
    while True:
        raw = prompt(text, str(default))
        try:
            val = int(raw)
            if min_val <= val <= max_val:
                return val
            Display.error(f"Enter a number between {min_val} and {max_val}")
        except ValueError:
            Display.error("Invalid number")


def prompt_choice(options: List[str]) -> int:
    """Prompt for a numbered menu choice. Returns index (0 = back/exit)."""
    while True:
        raw = prompt("Choice").strip()
        try:
            val = int(raw)
            if 0 <= val <= len(options):
                return val
            Display.error(f"Enter 0–{len(options)}")
        except ValueError:
            Display.error("Enter a number")


def prompt_bytes(text: str, encoding: str = "utf-8") -> bytes:
    """Read a text input and encode it to bytes."""
    raw = prompt(text)
    return raw.encode(encoding)


def prompt_key_bytes(text: str, required_sizes: Optional[List[int]] = None) -> bytes:
    """Prompt for a hex or text key and return bytes."""
    raw = prompt(text + " (hex or text)")
    if raw.startswith("0x"):
        raw = raw[2:]
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        key = raw.encode()

    if required_sizes and len(key) not in required_sizes:
        Display.warn(f"Key is {len(key)} bytes; expected one of {required_sizes}. Padding/truncating.")
        target = min((s for s in required_sizes if s >= len(key)), default=required_sizes[-1])
        key = (key * ((target // len(key)) + 1))[:target]
    return key


def prompt_file(text: str, must_exist: bool = True) -> str:
    """Prompt for a file path."""
    while True:
        path = prompt(text)
        if not path:
            Display.error("Path cannot be empty")
            continue
        if must_exist and not Path(path).exists():
            Display.error(f"File not found: {path}")
            continue
        return path


def confirm(text: str) -> bool:
    """Yes/No confirmation prompt."""
    ans = prompt(f"{text} [y/N]").lower()
    return ans in ("y", "yes")


def show_result(label: str, value: Any) -> None:
    Display.result(label, value)


def show_bytes(label: str, data: bytes, max_len: int = 64) -> None:
    Display.result(label + " (hex)", Display.bytes_preview(data, max_len))
    if all(32 <= b < 127 for b in data[:max_len]):
        Display.result(label + " (text)", data[:max_len].decode(errors="replace"))


def pause() -> None:
    """Wait for user to press Enter."""
    try:
        input("\n  Press Enter to continue…")
    except (EOFError, KeyboardInterrupt):
        pass
