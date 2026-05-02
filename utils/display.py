"""Terminal display helpers — colours, banners, tables."""
import os
import sys
from typing import Any, List, Optional

# Force UTF-8 on Windows so box-drawing / symbols render correctly
if sys.platform == "win32":
    import io
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except Exception:
            pass

try:
    from colorama import init as colorama_init, Fore, Style, Back
    colorama_init(autoreset=True, convert=True)
    _HAS_COLOR = True
except ImportError:
    _HAS_COLOR = False

    class _Dummy:
        def __getattr__(self, _: str) -> str:
            return ""

    Fore = Style = Back = _Dummy()  # type: ignore


class Display:
    """Static helpers for rich terminal output."""

    BANNER = r"""
  ___             _          ___      _ _         ___
 / __|_ _ _  _ _ | |_ ___  / __|_  _(_) |_ ___  | _ \_ _ ___
| (__| '_| || | '_ \  _/ _ \__ \ || | |  _/ -_) |  _/ '_/ _ \
 \___|_|  \_, |_.__/\__\___/___/\_,_|_|\__\___| |_| |_| \___/
          |__/                                 v1.0
    """

    @staticmethod
    def banner() -> None:
        print(Fore.CYAN + Display.BANNER + Style.RESET_ALL)

    @staticmethod
    def header(title: str) -> None:
        width = 60
        bar = "=" * width
        print(f"\n{Fore.YELLOW}{bar}")
        print(f"  {title.upper()}")
        print(f"{bar}{Style.RESET_ALL}\n")

    @staticmethod
    def success(msg: str) -> None:
        print(f"{Fore.GREEN}[OK]  {msg}{Style.RESET_ALL}")

    @staticmethod
    def error(msg: str) -> None:
        print(f"{Fore.RED}[ERR] {msg}{Style.RESET_ALL}")

    @staticmethod
    def info(msg: str) -> None:
        print(f"{Fore.CYAN}[*]  {msg}{Style.RESET_ALL}")

    @staticmethod
    def warn(msg: str) -> None:
        print(f"{Fore.YELLOW}[!]  {msg}{Style.RESET_ALL}")

    @staticmethod
    def result(label: str, value: Any) -> None:
        print(f"  {Fore.WHITE}{label:<20}{Style.RESET_ALL}{Fore.GREEN}{value}{Style.RESET_ALL}")

    @staticmethod
    def separator() -> None:
        print(f"{Fore.BLUE}{'-' * 60}{Style.RESET_ALL}")

    @staticmethod
    def table(headers: List[str], rows: List[List[Any]], title: str = "") -> None:
        try:
            from tabulate import tabulate
            if title:
                Display.header(title)
            print(tabulate(rows, headers=headers, tablefmt="rounded_outline"))
        except ImportError:
            if title:
                print(f"\n{title}")
            col_w = [max(len(str(h)), max((len(str(r[i])) for r in rows), default=0))
                     for i, h in enumerate(headers)]
            row_fmt = "  ".join(f"{{:<{w}}}" for w in col_w)
            print(row_fmt.format(*headers))
            print("  ".join("-" * w for w in col_w))
            for row in rows:
                print(row_fmt.format(*[str(c) for c in row]))

    @staticmethod
    def bytes_preview(data: bytes, max_bytes: int = 32) -> str:
        preview = data[:max_bytes].hex()
        suffix = "..." if len(data) > max_bytes else ""
        return f"0x{preview}{suffix}"

    @staticmethod
    def menu(title: str, options: List[str], back_label: str = "Back") -> None:
        Display.header(title)
        for i, opt in enumerate(options, 1):
            print(f"  {Fore.CYAN}[{i}]{Style.RESET_ALL}  {opt}")
        print(f"  {Fore.CYAN}[0]{Style.RESET_ALL}  {back_label}")
        print()
