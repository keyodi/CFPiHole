import logging


class CustomFormatter(logging.Formatter):
    COLOR_CODES = {
        logging.DEBUG: "\x1b[38;20m",  # Grey
        logging.INFO: "\x1b[38;20m",  # Grey (same as debug for consistency)
        logging.WARNING: "\x1b[33;20m",  # Yellow
        logging.ERROR: "\x1b[31;20m",  # Red
        logging.CRITICAL: "\x1b[31;1m",  # Bold Red
    }
    RESET = "\x1b[0m"
    YELLOW = "\x1b[33;20m"
    GREEN = "\x1b[33;92m"
    FORMAT = "%(message)s"

    def format(self, record):
        log_fmt = f"{self.COLOR_CODES.get(record.levelno)}{self.FORMAT}{self.RESET}"
        return logging.Formatter(log_fmt).format(record)

    @staticmethod
    def configure_logger(name: str, level=logging.INFO):
        logger = logging.getLogger(name)
        logger.setLevel(level)

        # Create a console handler with custom formatter
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_handler.setFormatter(CustomFormatter())

        # Add the handler to the logger and disable propagation
        logger.addHandler(console_handler)
        logger.propagate = False

        return logger
