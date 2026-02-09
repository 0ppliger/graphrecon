from dns.name import Name
from dns.resolver import NoAnswer
from dns.asyncresolver import Resolver
from dns.exception import DNSException
import dns.rdatatype

from ..logger import getLogger

logger = getLogger(__name__)


async def ensure_domain(
        domain: Name,
        resolver: Resolver
):
    rdtype = dns.rdatatype.from_text("A")
    try:
        await resolver.resolve(domain, rdtype)
        logger.debug(f"check domain:{domain}:{True}")
    except NoAnswer as e:
        logger.debug(f"check domain:{domain}:{True}:{type(e)}")
    except DNSException as e:
        logger.debug(f"check domain:{domain}:{False}:{type(e)}")
        raise
