from __future__ import annotations

import logging
from typing import Dict, Optional


class CustomFormatter(logging.Formatter):
    """Apply ANSI color codes to log messages based on log level."""

    COLORS: Dict[int, str] = {
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
        """Format a LogRecord with ANSI color codes."""
        color = self.COLORS.get(record.levelno, self.RESET)
        original_msg = record.msg
        record.msg = f"{color}{record.msg}{self.RESET}"
        formatted = super().format(record)
        record.msg = original_msg
        return formatted

    @staticmethod
    def configure_logger(name: str, level: int = logging.INFO) -> logging.Logger:
        """Create and return a named logger with a colored StreamHandler."""
        logger = logging.getLogger(name)

        # Avoid adding duplicate handlers to the same logger.
        if logger.handlers:
            return logger

        logger.setLevel(level)
        logger.propagate = False

        handler = logging.StreamHandler()
        handler.setLevel(level)
        handler.setFormatter(CustomFormatter("%(message)s"))
        logger.addHandler(handler)

        return logger
