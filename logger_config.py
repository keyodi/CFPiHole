import logging


class CustomFormatter(logging.Formatter):
    """A logging formatter that applies ANSI color codes to log messages based on
    their severity level."""

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

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelno, self.RESET)
        record = logging.makeLogRecord(record.__dict__)
        record.msg = f"{color}{record.msg}{self.RESET}"
        return super().format(record)

    def configure_logger(name: str, level: int = logging.INFO) -> logging.Logger:
        """Create and return a named logger with a colored StreamHandler attached."""
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
