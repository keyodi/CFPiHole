import logging

RESET  = "\033[0m"
WHITE  = "\033[97m"   # used for variable values
COLORS = {
    logging.DEBUG:    "\033[36m",   # cyan
    logging.INFO:     "\033[32m",   # green
    logging.WARNING:  "\033[33m",   # yellow
    logging.ERROR:    "\033[31m",   # red
    logging.CRITICAL: "\033[1;31m", # bold red
}

def v(value):
    """Wrap a variable value in white so it stands out in a colored log line."""
    return f"{WHITE}{value}{RESET}"

class ColorFormatter(logging.Formatter):
    def format(self, record):
        color = COLORS.get(record.levelno, RESET)
        record.msg = f"{color}{record.msg}{RESET}"
        return super().format(record)

def setup():
    """Call once at startup to configure the root handler."""
    handler = logging.StreamHandler()
    handler.setFormatter(ColorFormatter("%(message)s"))
    logging.basicConfig(level=logging.INFO, handlers=[handler])
