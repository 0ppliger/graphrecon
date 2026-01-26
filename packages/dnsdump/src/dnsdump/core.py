import dns.rdata
import dns.rdatatype
from dns.name import Name
from dns.resolver import BaseResolver
from typing import Generator, Optional
from dns.rdata import GenericRdata
from dns.exception import DNSException

from common.logger import getLogger

logger = getLogger(__name__)

YieldValue = tuple[str, Optional[GenericRdata], Optional[Exception]]
DumpDNSGenerator = Generator[YieldValue, None, None]

RDTYPES = [
    name for name, value in dns.rdatatype.__dict__.items()
    if name.isupper()
    and isinstance(value, int)
    and not dns.rdatatype.is_metatype(value)]


def dump_dns_records(
        domain: Name,
        resolver: BaseResolver
) -> DumpDNSGenerator:

    for rdtype in RDTYPES:
        try:
            logger.debug(f"try record:{rdtype}")
            answers = resolver.resolve(domain, rdtype)
            for rdata in answers:
                yield (rdtype, rdata, None)

        except DNSException as e:
            logger.debug(type(e).__name__)
            yield (rdtype, None, e)
