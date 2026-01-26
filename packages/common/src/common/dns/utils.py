from dns.name import Name
from dns.resolver import Resolver, NoAnswer
from dns.exception import DNSException
import dns.rdatatype

from ..logger import getLogger

logger = getLogger(__name__)


def ensure_domain(
        domain: Name,
        resolver: Resolver
):
    rdtype = dns.rdatatype.from_text("A")
    try:
        resolver.resolve(domain, rdtype)
        logger.debug(f"check domain:{domain}:{True}")
    except NoAnswer as e:
        logger.debug(f"check domain:{domain}:{True}:{type(e)}")
    except DNSException as e:
        logger.debug(f"check domain:{domain}:{False}:{type(e)}")
        raise
