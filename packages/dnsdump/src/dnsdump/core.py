import asyncio
import dns.rdata
import dns.rdatatype
from dns.name import Name
from dns.asyncresolver import Resolver
from typing import Generator, Optional
from dns.rdata import GenericRdata
from dns.exception import DNSException, Timeout

from common.logger import getLogger

logger = getLogger(__name__)

YieldValue = tuple[str, Optional[GenericRdata], Optional[Exception]]
DumpDNSGenerator = Generator[YieldValue, None, None]

RDTYPES = [
    name for name, value in dns.rdatatype.__dict__.items()
    if name.isupper()
    and isinstance(value, int)
    and not dns.rdatatype.is_metatype(value)]


async def _resolve_with_retry(
    resolver: Resolver,
    domain: Name,
    rdtype: str,
    retries: int,
    retry_delay: float,
):
    last_exc: Exception | None = None
    for attempt in range(retries):
        try:
            return await resolver.resolve(domain, rdtype)
        except (Timeout, OSError) as e:
            last_exc = e
            if attempt < retries - 1:
                logger.debug(
                    "resolve %s %s failed (attempt %s/%s): %s, retrying in %.1fs",
                    domain, rdtype, attempt + 1, retries, e, retry_delay,
                )
                await asyncio.sleep(retry_delay)
            else:
                raise
    assert last_exc is not None
    raise last_exc


async def dump_dns_records(
        domain: Name,
        resolver: Resolver,
        retries: int = 3,
        retry_delay: float = 1.0,
) -> DumpDNSGenerator:

    logger.debug(f"dump_dns_records:all:{RDTYPES}")

    for rdtype in RDTYPES:
        logger.debug(f"dump_dns_records:test:{rdtype}")
        try:
            logger.debug(f"try record:{rdtype}")
            answers = await _resolve_with_retry(
                resolver, domain, rdtype, retries, retry_delay
            )
            for rdata in answers:
                logger.debug(f"rdata:{rdata}")
                yield (rdtype, rdata, None)

        except DNSException as e:
            logger.debug(type(e).__name__)
            yield (rdtype, None, e)
