import logging

RESET = "\033[0m"
WHITE = "\033[97m"  # Used for variable values.
COLORS = {
    logging.DEBUG: "\033[36m",  # Cyan.
    logging.INFO: "\033[32m",  # Green.
    logging.WARNING: "\033[33m",  # Yellow.
    logging.ERROR: "\033[31m",  # Red.
    logging.CRITICAL: "\033[1;31m",  # Bold red.
}


def highlight(value: object) -> str:
    """Wrap a variable value in white in a colored log line."""
    return f"{WHITE}{value}{RESET}"


class ColorFormatter(logging.Formatter):
    """Color each log line by severity."""

    def format(self, record: logging.LogRecord) -> str:
        color = COLORS.get(record.levelno, RESET)
        message = super().format(record)
        # Re-apply the line color after every highlighted value.
        return f"{color}{message.replace(RESET, RESET + color)}{RESET}"


def setup_logging() -> None:
    """Call once at startup to configure the root handler."""
    handler = logging.StreamHandler()
    handler.setFormatter(ColorFormatter("%(message)s"))
    logging.basicConfig(level=logging.INFO, handlers=[handler])
