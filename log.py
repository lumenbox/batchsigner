import logging
import sys


def setup_custom_logger(name, log_level):
    logger = logging.getLogger(name)
    formatter = logging.Formatter(fmt='%(levelname)s - %(module)s - %(message)s')
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(log_level)
    return logger
