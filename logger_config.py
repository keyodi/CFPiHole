from __future__ import annotations

import logging


class CustomFormatter(logging.Formatter):
    """Apply ANSI color codes to log messages based on log level."""

    COLORS: dict[int, str] = {
        logging.DEBUG: "\x1b[38;20m",    # Grey
        logging.INFO: "\x1b[37;20m",     # White
        logging.WARNING: "\x1b[33;20m",  # Yellow
        logging.ERROR: "\x1b[31;20m",    # Red
        logging.CRITICAL: "\x1b[31;1m",  # Bold Red
    }
    RESET = "\x1b[0m"
    YELLOW = "\x1b[33;20m"
    GREEN = "\x1b[92m"

    def __init__(self, fmt: str | None = "%(message)s") -> None:
        super().__init__(fmt)

    def format(self, record: logging.LogRecord) -> str:
        """Format a LogRecord and wrap the rendered line in an ANSI color code."""
        color = self.COLORS.get(record.levelno, self.RESET)
        formatted = super().format(record)
        return f"{color}{formatted}{self.RESET}"

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
