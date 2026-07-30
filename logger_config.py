"""CFPiHole — Colored logger utilities.

This module provides a small logging Formatter that adds ANSI color codes to
console output and a helper to configure named loggers consistently.
"""
from __future__ import annotations

import logging
from typing import Optional


class CustomFormatter(logging.Formatter):
    """A logging formatter that applies ANSI color codes to log messages based on
    their severity level.

    The class exposes a few color constants that other modules can reference
    when emitting colored informational messages.
    """

    COLORS = {
        logging.DEBUG: "\x1b[38;20m",    # Grey
        logging.INFO: "\x1b[37;20m",     # White
        logging.WARNING: "\x1b[33;20m",  # Yellow
        logging.ERROR: "\x1b[31;20m",    # Red
        logging.CRITICAL: "\x1b[31;1m",  # Bold Red
    }
    RESET = "\x1b[0m"
    YELLOW = "\x1b[33;20m"
    GREEN = "\x1b[92m"

    def __init__(self, fmt: Optional[str] = "%(message)s") -> None:
        super().__init__(fmt)

    def format(self, record: logging.LogRecord) -> str:
        """Format a LogRecord and wrap the message in the ANSI color sequence.

        The method preserves the underlying logging machinery while only altering
        the textual message that is displayed.
        """
        color = self.COLORS.get(record.levelno, self.RESET)
        # Make a shallow copy so we don't permanently mutate the record.
        record_copy = logging.makeLogRecord(record.__dict__)
        record_copy.msg = f"{color}{record_copy.msg}{self.RESET}"
        return super().format(record_copy)

    @staticmethod
    def configure_logger(name: str, level: int = logging.INFO) -> logging.Logger:
        """Create and return a named logger with a colored StreamHandler attached.

        If a logger with handlers already exists we return it unchanged. This
        keeps behavior predictable when this helper is called multiple times.
        """
        logger = logging.getLogger(name)

        if logger.hasHandlers():
            return logger

        logger.setLevel(level)
        logger.propagate = False

        handler = logging.StreamHandler()
        handler.setLevel(level)
        handler.setFormatter(CustomFormatter("%(message)s"))
        logger.addHandler(handler)

        return logger
