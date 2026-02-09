from dns import name
from dns.rdata import Rdata
from dns.asyncresolver import Resolver
from dns.exception import DNSException
from oam_client import AsyncBrokerClient
from asset_model import FQDN
from typing import Callable, Awaitable

from common.dns.utils import ensure_domain
from common.ratelimiter import RateLimiter

from .store import dispatch
from .core import dump_dns_records, DumpDNSGenerator


class DumpDNSCommand:

    IS_ASYNC: bool = True

    domain: name.Name
    resolver: Resolver
    dump:  DumpDNSGenerator
    store: AsyncBrokerClient
    ratelimiter: RateLimiter
    on_success: Callable[[str, Rdata], Awaitable[None]]
    on_failure: Callable[[str], Awaitable[None]]

    def __init__(
        self,
        domain: str,
        store: AsyncBrokerClient,
        on_success: Callable[[str, Rdata], None],
        on_failure: Callable[[str], None],
        ratelimiter_delay: int = 300,
        ratelimiter_batch: int = 5,
        resolv: str = "/etc/resolv.conf",
        timeout: int = 5000,
        lifetime: int = 10000,
        retries: int = 3,
        retry_delay: int = 1000,
    ):
        try:
            self.domain = name.from_text(domain)
        except DNSException:
            raise

        try:
            self.resolver = Resolver(
                filename=resolv,
                configure=True)
        except DNSException:
            raise

        self.resolver.timeout = timeout / 1000.0
        self.resolver.lifetime = lifetime / 1000.0
        self.retries = retries
        self.retry_delay = retry_delay / 1000.0
        self.store = store

        self.on_success = on_success
        self.on_failure = on_failure

        if ratelimiter_batch < 1:
            raise ValueError(
                "rate limiter's batch size must be greather than 0")

        if ratelimiter_delay < 0:
            raise ValueError(
                "rate limiter's batch size must be greather or equal to 0")

        try:
            self.ratelimiter = RateLimiter(
                ratelimiter_batch,
                ratelimiter_delay)
        except ValueError:
            raise

    async def run(self):

        print(FQDN(self.domain.to_text(True)))
        self.base = await self.store.create_entity(FQDN(self.domain.to_text(True)))

        async def success_handler(rdtype: str, rdata: Rdata):
            try:
                data = await dispatch(self.store, self.base, rdtype, rdata)
            except Exception as e:
                raise e
            self.on_success(rdtype, data)

        async def failure_handler(rdtype: str):
            self.on_failure(rdtype)

        try:
            await ensure_domain(self.domain, self.resolver)
        except DNSException:
            raise

        self.dump = dump_dns_records(
            self.domain,
            self.resolver,
            retries=self.retries,
            retry_delay=self.retry_delay,
        )
        async for rdtype, rdata, err in self.dump:
            await self.ratelimiter.try_acquire_async()
            if rdata is None:
                await failure_handler(rdtype)
                continue

            await success_handler(rdtype, rdata)
