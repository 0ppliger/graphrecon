from dns.name import from_text, Name
from dns.exception import DNSException
from dns.asyncresolver import resolve_name
from typing import TextIO, Optional, Callable
from asset_model import FQDN
from asset_model import SimpleRelation
from graphrecon_lib import Context
import asyncio
import logging


class DNSFuzzException(Exception):
    pass


class DNSFuzzInvalidDomain(DNSFuzzException):
    def __init__(self, domain: str, message: str):
        super().__init__(f"Invalid domain name '{domain}': {message}")
        self.domain = domain


class Delay:
    def __init__(self, value: int):
        if value < 0:
            raise ValueError("Delay cannot be lower than 0")

        self.__value = value

    @property
    def milliseconds(self) -> int:
        return self.__value

    @property
    def seconds(self) -> float:
        return self.__value / 1000


class BatchSize:
    def __init__(self, value: int):
        if value < 1:
            raise ValueError("Batch size must be at least 1")

        self.__value = value

    def is_new(self, index: int) -> bool:
        return index % self.__value == 0


class RateLimiter:
    delay: Delay
    batch_size: BatchSize

    def __init__(self, batch_size: int, delay: int):
        self.delay = Delay(delay)
        self.batch_size = BatchSize(batch_size)

    async def apply(self, index: int):
        if self.batch_size.is_new(index):
            await asyncio.sleep(self.delay.seconds)


class DNSFuzz:
    domain: Name
    wordlist: TextIO
    rate_limiter: RateLimiter
    on_success: Callable[[str], None]
    on_failure: Callable[[str], None]

    def __init__(
            self,
            domain: str,
            wordlist: str,
            rate_limiter_delay: int = 0,
            rate_limiter_batch: int = 5,
            on_success: Optional[Callable[[str], None]] = None,
            on_failure: Optional[Callable[[str], None]] = None
    ):

        try:
            self.domain = from_text(domain)
        except DNSException as e:
            raise DNSFuzzInvalidDomain(domain, str(e))

        try:
            self.wordlist = open(wordlist)
        except OSError as e:
            raise e

        try:
            self.rate_limiter = RateLimiter(
                rate_limiter_batch,
                rate_limiter_delay)
        except ValueError as e:
            raise e

        self.on_success = on_success
        self.on_failure = on_failure

    async def fuzz(self, ctx: Context):

        async def __check_subdomain(self, ctx: Context, subdomain: Name):

            async def __check(subdomain: Name) -> bool:
                try:
                    await resolve_name(subdomain)
                    return True
                except Exception as e:
                    logging.debug(e)
                    return False

            if await __check(subdomain):
                print(f"found: {subdomain.to_text(True)}")
                entity = ctx.db.create_asset(FQDN(subdomain.to_text(True)))
                ctx.db.create_relation(SimpleRelation("node"), ctx.config.apex, entity)
                if self.on_success is not None:
                    self.on_success(subdomain.to_text(True))
                return subdomain
            else:
                if self.on_failure is not None:
                    self.on_failure(subdomain.to_text(True))

        ctx.config.apex = ctx.db.create_asset(FQDN(self.domain.to_text(True)))

        for index, word in enumerate(self.wordlist):
            await self.rate_limiter.apply(index)

            subdomain_name = f"{word.strip()}.{self.domain.to_text(True)}"
            try:
                subdomain = from_text(subdomain_name)
            except Exception:
                logging.warning(f"fail to parse '{subdomain_name}'")
                continue

            yield asyncio.create_task(
                __check_subdomain(self, ctx, subdomain))
