"""Centralised logging for CryptoSuite Pro."""
import logging
import logging.handlers
import os
from pathlib import Path


_LOG_DIR = Path(__file__).parent.parent / "logs"
_LOG_FILE = _LOG_DIR / "cryptosuite.log"
_LOGGERS: dict[str, logging.Logger] = {}


def _ensure_log_dir() -> None:
    _LOG_DIR.mkdir(exist_ok=True)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger. Creates file + console handlers on first call."""
    if name in _LOGGERS:
        return _LOGGERS[name]

    _ensure_log_dir()
    logger = logging.getLogger(f"cryptosuite.{name}")
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)

        fmt = logging.Formatter(
            "%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        # Rotating file handler (5 MB × 3 backups)
        fh = logging.handlers.RotatingFileHandler(
            _LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
        )
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)

        # Console handler — only warnings and above
        ch = logging.StreamHandler()
        ch.setLevel(logging.WARNING)
        ch.setFormatter(fmt)

        logger.addHandler(fh)
        logger.addHandler(ch)
        logger.propagate = False

    _LOGGERS[name] = logger
    return logger
