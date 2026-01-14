import dns.rdata
import dns.rdatatype
import dns.resolver
from datetime import datetime
from dataclasses import dataclass
from typing import Optional
from graphrecon_lib import Context
from asset_model import FQDN
from asset_store.events.events import Event
from dnsdump.handlers import dispatch

class DNSDumpEvent:
    def __init__(self, rdtype: str):
        self.rdtype = rdtype
        self.emitted_at = datetime.now()

class DNSDumpAnswer(DNSDumpEvent):
    def __init__(self, rdtype: str, data: dict):
        super().__init__(rdtype)
        self.data = data

class DNSDumpNoAnswer(DNSDumpEvent):
    pass

class DNSDumpQueryFail(DNSDumpEvent):
    pass

class DNSDump:
    ctx: Context

    RDTYPES = [
        name for name, value in dns.rdatatype.__dict__.items()
        if name.isupper() and isinstance(value, int) and not dns.rdatatype.is_metatype(value)]
    
    def __init__(self, ctx: Context):
        self.ctx = ctx
        
        try:
            self._resolver = dns.resolver.Resolver(
                filename=self.ctx.config.resolv,
                configure=True)
        except dns.resolver.NoResolverConfiguration as e:
            raise e

    def soa_check(self, domain: str) -> bool:
        try:
            self._resolver.resolve(domain, 'SOA')
            return True
        except dns.resolver.NXDOMAIN:
            return False
        except dns.exception.DNSException:
            return True
        
    def dump_domain(self, domain: str):
        if not self.soa_check(domain):
            raise ValueError(f"domain '{domain.to_text(True)}' failed SOA check")

        self.ctx.base = self.ctx.db.create_asset(FQDN(domain))
        
        for rdtype in self.RDTYPES:
            try:
                answers = self._resolver.resolve(domain, rdtype)
                for rdata in answers:
                    data = dispatch(self.ctx, rdtype, rdata)
                    yield DNSDumpAnswer(rdtype, data)
                    
            except dns.resolver.NoAnswer as e:
                yield DNSDumpNoAnswer(rdtype)
            except dns.resolver.NoNameservers as e:
                yield DNSDumpQueryFail(rdtype)

        
