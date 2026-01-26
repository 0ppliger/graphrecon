import os
import logging

LOGLEVEL = os.getenv("LOGLEVEL", "WARNING").upper()

logging.basicConfig(
    level=getattr(logging, LOGLEVEL, logging.WARNING))

getLogger = logging.getLogger
