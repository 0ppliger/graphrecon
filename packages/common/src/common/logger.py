import os
import logging

if "GR_LOGLEVEL" in os.environ:
    LOGLEVEL = os.environ["GR_LOGLEVEL"].upper()
else:
    LOGLEVEL = os.getenv("LOGLEVEL", "WARNING").upper()

__loglevel = getattr(logging, LOGLEVEL, logging.WARNING)

logging.basicConfig(
    level=__loglevel)


def getLogger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.level = __loglevel
    return logger
