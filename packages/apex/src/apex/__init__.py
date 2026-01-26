from os import getenv
from dns.name import Name, from_text, BadEscape, EmptyLabel
import logging


loglevel = getenv("LOG_LEVEL", "WARNING").upper()

logging.basicConfig(
    level=getattr(logging, loglevel, logging.WARNING))

logger = logging.getLogger("apex")


def apex(domain: str) -> str:
    """
    @parameters
    domain: str - A domain or a subdomain

    @returns
    the corresponding apex domain

    @raises
    InvalidDomain(domain: str)
    """
    logger.debug(f"parse:{domain}")
    try:
        _domain = from_text(domain)
    except (BadEscape, EmptyLabel):
        raise InvalidDomain(domain)

    try:
        return __apex_backend(_domain).to_text(True)
    except InvalidDomain as e:
        raise e
