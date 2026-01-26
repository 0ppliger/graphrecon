from dns import name
from dns.rdata import Rdata
from dns.resolver import Resolver
from dns.exception import DNSException
from asset_store.repository.repository import Repository
from typing import Callable

from asset_model import FQDN
from common.dns.utils import ensure_domain
from common.ratelimiter import RateLimiter

from .store import dispatch
from .core import dump_dns_records, DumpDNSGenerator


class DumpDNSCommand:

    IS_ASYNC: bool = False

    dump:  DumpDNSGenerator
    store: Repository
    ratelimiter: RateLimiter
    on_success: Callable[[str, Rdata], None]
    on_failure: Callable[[str], None]

    def __init__(
        self,
        domain: str,
        store: Repository,
        on_success: Callable[[str, Rdata], None],
        on_failure: Callable[[str], None],
        ratelimiter_delay: int = 300,
        ratelimiter_batch: int = 5,
        resolv: str = "/etc/resolv.conf",
    ):
        try:
            _domain = name.from_text(domain)
        except DNSException:
            raise

        try:
            _resolver = Resolver(
                filename=resolv,
                configure=True)
        except DNSException:
            raise

        self.store = store

        base = self.store.create_asset(FQDN(_domain.to_text(True)))

        def success_handler(rdtype: str, rdata: Rdata):
            data = dispatch(self.store, base, rdtype, rdata)
            on_success(rdtype, data)

        self.on_success = success_handler

        def failure_handler(rdtype: str):
            on_failure(rdtype)

        self.on_failure = failure_handler

        try:
            ensure_domain(_domain, _resolver)
        except DNSException:
            raise

        self.dump = dump_dns_records(_domain, _resolver)

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

    def run(self):
        for rdtype, rdata, err in self.dump:
            self.ratelimiter.try_acquire()
            if rdata is None:
                self.on_failure(rdtype)
                continue

            self.on_success(rdtype, rdata)
