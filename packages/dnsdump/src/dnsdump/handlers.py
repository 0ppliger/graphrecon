from typing import Optional, Type, Mapping, Callable
from graphrecon_lib import Context
from dns.rdata import Rdata
import dns.rdtypes.IN.A
import dns.rdtypes.IN.AAAA
import dns.rdtypes.ANY.TXT
import dns.rdtypes.ANY.CNAME
import dns.rdtypes.ANY.NS
import dns.rdtypes.ANY.SOA
import dns.rdtypes.ANY.MX
import dns.rdtypes.IN.SRV
from asset_model import OAMObject
from asset_model import IPAddress, IPAddressType
from asset_model import FQDN
from asset_model import Identifier, IdentifierType
from asset_model import BasicDNSRelation
from asset_model import PrefDNSRelation
from asset_model import SRVDNSRelation
from asset_model import SourceProperty
from asset_model import DNSRecordProperty
from asset_store.types import Entity, Edge
from asset_store.events.events import Event

HandlerCallback = Callable[[Context, str, dns.rdata.Rdata], dict]

handlers: dict[Type[dns.rdata.Rdata], HandlerCallback] = {}

def add_source(ctx: Context, o: Entity | Edge) -> Optional[Event]:
    if ctx.config.nosource:
        return None
    
    if type(o) is Entity:
        return ctx.db.create_entity_property(
            o, SourceProperty(source=ctx.source, confidence=100))
    if type(o) is Edge:
        return ctx.db.create_edge_property(
            o, SourceProperty(source=ctx.source, confidence=100))


def dispatch(ctx: Context, rdtype: str, rdata: Rdata) -> dict:
    handler = handlers.get(type(rdata))
    if handler is None:
        return handle_default(ctx, rdtype, rdata)
    return handler(ctx, rdtype, rdata)

def handle_default(ctx, rdtype, rdata) -> list[Event]:
    data = { "value": rdata.to_text() }

    ctx.db.create_entity_property(
        ctx.base,
        DNSRecordProperty(
            "dns_record",
            data["value"],
            rrtype = rdata.rdtype,
            rrname = rdtype
        ))

    return data

    
def handle(rdtype: Type[dns.rdata.Rdata]):
    def decorator(func: HandlerCallback) -> HandlerCallback:
        handlers[rdtype] = func
        return func
    return decorator

@handle(dns.rdtypes.IN.A.A)
def handle_a(ctx, rdtype, rdata):
    data = IPAddress(rdata.address, IPAddressType.IPv4)
    ip = ctx.db.create_asset(data)
    add_source(ctx, ip)
    
    rel = ctx.db.create_relation(
        BasicDNSRelation(
            "dns_record",
            rdata.rdtype,
            rrname = rdtype),
        ctx.base,
        ip)
    add_source(ctx, rel)
    return data.to_dict()


@handle(dns.rdtypes.IN.AAAA.AAAA)
def handle_aaaa(ctx, rdtype, rdata):
    data = IPAddress(rdata.address, IPAddressType.IPv6)
    ip_entity = ctx.db.create_asset(data)
    add_source(ctx, ip_entity)
    
    rel = ctx.db.create_relation(
        BasicDNSRelation("dns_record", rdata.rdtype,
            rrname = rdtype),
        ctx.base,
        ip_entity)
    add_source(ctx, rel)
    return data.to_dict()

@handle(dns.rdtypes.ANY.CNAME.CNAME)
def handle_cname(ctx, rdtype, rdata):
    data = FQDN(rdata.target.to_text(True))
    fqdn_entity = ctx.db.create_asset(data)
    add_source(ctx, fqdn_entity)
    
    rel = ctx.db.create_relation(
        BasicDNSRelation("dns_record", rdata.rdtype,
            rrname = rdtype),
        ctx.base,
        fqdn_entity)
    add_source(ctx, rel)
    return data.to_dict()

@handle(dns.rdtypes.ANY.NS.NS)
def handle_ns(ctx, rdtype, rdata):
    data = FQDN(rdata.target.to_text(True))
    fqdn_entity = ctx.db.create_asset(data)
    add_source(ctx, fqdn_entity)
    
    rel = ctx.db.create_relation(
        BasicDNSRelation("dns_record", rdata.rdtype,
            rrname = rdtype),
        ctx.base,
        fqdn_entity)
    add_source(ctx, rel) 
    return data.to_dict()

@handle(dns.rdtypes.ANY.SOA.SOA)
def handle_soa(ctx, rdtype, rdata):
        
    def rname_to_email(rname: str) -> str:
        name = dns.name.from_text(rname)
        local_part = name.labels[0].decode()
        domain = ".".join(label.decode() for label in name.labels[1:])
        return f"{local_part}@{domain}"

    data = {"value": rdata.to_text()}
    
    mname_value = rdata.mname.to_text(True)
    mname = FQDN(mname_value)
    mname_entity = ctx.db.create_asset(mname)
    add_source(ctx, mname_entity)
    
    rname_value = rname_to_email(rdata.rname.to_text(True))
    rname = Identifier(
        rname_value,
        rname_value,
        type=IdentifierType.EmailAddress)
    rname_entity = ctx.db.create_asset(rname)
    add_source(ctx, rname_entity)
    
    extra = {
        "mname": mname_value,
        "rname": rname_value,
        "serial": rdata.serial,
        "refresh": rdata.refresh,
        "retry": rdata.retry,
        "expire": rdata.expire,
        "minimum": rdata.minimum
    }

    mname_rel = ctx.db.create_relation(
        BasicDNSRelation(
            "dns_record",
            rdata.rdtype,
            rrname = rdtype,
            extra = extra),
        ctx.base,
        mname_entity)
    add_source(ctx, mname_rel)
    
    rname_rel = ctx.db.create_relation(
        BasicDNSRelation(
            "dns_record",
            rdata.rdtype,
            rrname = rdtype,
            extra = extra),
        ctx.base,
        rname_entity)
    add_source(ctx, rname_rel)

    return data

@handle(dns.rdtypes.ANY.MX.MX)
def handle_mx(ctx, rdtype, rdata):
    data = FQDN(rdata.exchange.to_text(True))
    fqdn_entity = ctx.db.create_asset(data)
    add_source(ctx, fqdn_entity)
    
    rel = ctx.db.create_relation(
        PrefDNSRelation(
            "dns_record",
            preference = rdata.preference,
            rrtype = rdata.rdtype,
            rrname = rdtype),
        ctx.base,
        fqdn_entity)
    add_source(ctx, rel)
    return data.to_dict()

@handle(dns.rdtypes.ANY.TXT.TXT)
def handle_txt(ctx, rdtype, rdata):
    data = { "value": ''.join([s.decode('utf-8') for s in rdata.strings]) }

    prop = ctx.db.create_entity_property(
        ctx.base,
        DNSRecordProperty(
            "dns_record",
            data["value"],
            rrtype = rdata.rdtype,
            rrname = rdtype
        ))
    add_source(ctx, prop)
    return data

@handle(dns.rdtypes.IN.SRV.SRV)
def handle_srv(ctx, rdtype, rdata):
    data = { "value": ''.join([s.decode('utf-8') for s in rdata.strings]) }

    ctx.db.create_entity_property(
        ctx.base,
        DNSRecordProperty(
            "dns_record",
            data["value"],
            rrtype = rdata.rdtype,
            rrname = rdtype
        ))
    return data
