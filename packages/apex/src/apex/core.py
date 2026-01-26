from dns.name import Name

from common.logger import getLogger

logger = getLogger(__name__)


def parse_labels(domain: Name) -> bool:
    valid = len(domain.labels) >= 3
    logger.debug(f"parse_labels:{domain}:{valid}")
    if not valid:
        raise ValueError(f"There is no apex domain for {domain}")


def is_apex(domain: Name) -> bool:
    p = len(domain.labels) == 3
    logger.debug(f"is_apex:{domain}:{p}")
    return p


def find_apex(domain: Name) -> Name:
    logger.debug(f"get_apex:try domain:{domain}")

    try:
        parse_labels(domain)
    except ValueError:
        raise

    if is_apex(domain):
        return domain

    parent = domain.parent()
    logger.debug(f"get_apex:try parent:{parent}")
    return find_apex(parent)
