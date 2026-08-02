from __future__ import annotations

import copy
import logging
from typing import Optional


class CustomFormatter(logging.Formatter):
    """A logging formatter that applies ANSI color codes to log messages.

    Keeps timestamps and levelnames while colorizing only the message text.
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

    def __init__(self, fmt: Optional[str] = "%(asctime)s %(levelname)s: %(message)s") -> None:
        super().__init__(fmt, datefmt="%Y-%m-%d %H:%M:%S")

    def format(self, record: logging.LogRecord) -> str:
        # copy record to avoid modifying shared object
        record_copy = copy.copy(record)
        color = self.COLORS.get(record.levelno, "")
        # Use getMessage to respect %-formatting and args
        record_copy.msg = f"{color}{record_copy.getMessage()}{self.RESET}"
        record_copy.args = ()
        return super().format(record_copy)

    @classmethod
    def configure_logger(cls, name: str, level: int = logging.INFO) -> logging.Logger:
        """Create and return a named logger with a colored StreamHandler attached.

        This is idempotent and will not add duplicate handlers if called multiple times.
        """
        logger = logging.getLogger(name)
        logger.setLevel(level)
        logger.propagate = False

        # add handler only if none of the existing handlers are StreamHandler
        if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
            handler = logging.StreamHandler()
            handler.setLevel(level)
            handler.setFormatter(cls())
            logger.addHandler(handler)

        return logger


# Backwards-compatible function name for callers that prefer a function
def configure_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    return CustomFormatter.configure_logger(name, level)
