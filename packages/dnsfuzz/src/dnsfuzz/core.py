from dataclasses import dataclass
from dns.name import Name, from_text
from dns.asyncresolver import Resolver as AsyncResolver
from dns.resolver import Resolver as SyncResolver
from typing import TextIO, Callable
from dns.exception import DNSException
import asyncio

from common.logger import getLogger

logger = getLogger(__name__)


@dataclass
class DNSFuzz:
    domain:         Name
    wordlist:       TextIO
    resolver: AsyncResolver
    on_success:     Callable[[Name], None]
    on_failure:     Callable[[Name], None]

    async def does_domain_exists(self, domain: Name) -> bool:
        logger.debug(f"does_domain_exists:{domain}")
        try:
            await self.resolver.resolve_name(domain)
            logger.debug(f"does_domain_exists:{domain}:{True}")
            return True
        except DNSException:
            logger.debug(f"does_domain_exists:{domain}:{False}")
            return False
        except Exception:
            raise

    async def fuzz_domain(self, domain: Name):
        if await self.does_domain_exists(domain):
            self.on_success(domain)
        else:
            self.on_failure(domain)

    async def fuzz(self):
        for line, word in enumerate(self.wordlist):
            word = word.strip()
            logger.debug(f"fuzz:try word:{word}")

            try:
                subdomain = from_text(f"{word}.{self.domain}")
            except DNSException:
                logger.warning(
                    f"fuzz:currupted wordlist entry at line {line}. "
                    f"'{word}' is not a valid subdomain label.")
                continue

            yield asyncio.create_task(
                self.fuzz_domain(subdomain))
