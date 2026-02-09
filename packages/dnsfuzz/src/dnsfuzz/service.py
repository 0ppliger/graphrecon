from dns import name
from typing import Callable
from asyncio import Task, gather
from oam_client import BrokerClient
from dns.exception import DNSException
from dns.asyncresolver import Resolver as AsyncResolver
from dns.resolver import Resolver as SyncResolver

from common.logger import getLogger
from common.ratelimiter import RateLimiter
from common.dns.utils import ensure_domain

from .core import DNSFuzz
from .store import store_fqdn

logger = getLogger(__name__)


class FuzzDNSCommand:
    """
    Enumerate all subdomains for a given DOMAIN using a WORDLIST.
    """

    IS_ASYNC = True

    core: DNSFuzz
    ratelimiter: RateLimiter
    store: BrokerClient

    def __init__(
            self,
            domain: str,
            wordlist: str,
            on_success: Callable[[str], None],
            on_failure: Callable[[str], None],
            store: BrokerClient,
            ratelimiter_delay: int = 300,
            ratelimiter_batch: int = 5,
            disable_store: bool = False,
            resolv: str = "/etc/resolv.conf",
    ):
        """
        Instanciate the DNSFuzzService.

        :param domain: the target domain
        :param wordlist: the path of the wordlist file
        :param on_success: function called when a subdomain exists
        :param on_failure: function called when a subdomain don't exists
        :param resolv: path to the resolv.conf file
        :param store: the asset store
        :param ratelimiter_delay: delay between each requests batch
        :param ratelimiter_batch: size of each requests batch
        :param disable_store: disable asset store
        :raises InvalidDomain: when domain cannot be turned into a Name object
        :raises OSError: when wordlist cannot be opened
        :raises ValueError: when rate limiter receive impossible values
        """
        try:
            self.domain = name.from_text(domain)
        except DNSException:
            raise

        try:
            self.wordlist = open(wordlist)
        except OSError as e:
            raise e

        try:
            self.resolver = AsyncResolver(
                filename=resolv,
                configure=True)
        except DNSException:
            raise

        def success_handler(domain: name.Name):
            domain_name = domain.to_text(True)
            logger.debug(f"find:{domain_name}")

            if not disable_store:
                store_fqdn(store, domain)

            on_success(domain_name)

        def failure_handler(domain: name.Name):
            domain_name = domain.to_text(True)
            logger.debug(f"try:{domain_name}")
            on_failure(domain_name)

        self.core = DNSFuzz(
            self.domain,
            self.wordlist,
            self.resolver,
            success_handler,
            failure_handler)

        try:
            self.ratelimiter = RateLimiter(
                ratelimiter_batch,
                ratelimiter_delay)
        except ValueError:
            raise

        self.store = store

    async def run(self):
        try:
            await ensure_domain(self.domain, self.resolver)
        except DNSException:
            raise

        tasks: list[Task] = []
        async for sub in self.core.fuzz():
            await self.ratelimiter.try_acquire_async()
            tasks.append(sub)

        await gather(*tasks)
