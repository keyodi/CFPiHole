import logging


class CustomFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG: "\x1b[38;20m",    # Grey
        logging.INFO: "\x1b[38;20m",     # Grey
        logging.WARNING: "\x1b[33;20m",  # Yellow
        logging.ERROR: "\x1b[31;20m",    # Red
        logging.CRITICAL: "\x1b[31;1m",  # Bold Red
    }
    RESET = "\x1b[0m"
    YELLOW = "\x1b[33;20m"
    GREEN = "\x1b[33;92m"

    def format(self, record):
        color = self.COLORS.get(record.levelno, self.RESET)
        record.msg = f"{color}{record.msg}{self.RESET}"
        return super().format(record)

    @staticmethod
    def configure_logger(name: str, level=logging.INFO):
        logger = logging.getLogger(name)

        # If logger already has handlers
        if logger.hasHandlers():
            return logger

        logger.setLevel(level)
        logger.propagate = False

        # Create handler and assign the formatter
        handler = logging.StreamHandler()
        handler.setFormatter(CustomFormatter("%(message)s"))
        logger.addHandler(handler)

        return logger

