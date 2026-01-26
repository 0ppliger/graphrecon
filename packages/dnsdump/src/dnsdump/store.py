from typing import Optional, Type, Callable
from dns.rdata import Rdata
import dns.rdtypes.IN.A
import dns.rdtypes.IN.AAAA
import dns.rdtypes.ANY.TXT
import dns.rdtypes.ANY.CNAME
import dns.rdtypes.ANY.NS
import dns.rdtypes.ANY.SOA
import dns.rdtypes.ANY.MX
import dns.rdtypes.IN.SRV
from asset_model import IPAddress, IPAddressType
from asset_model import FQDN
from asset_model import Identifier, IdentifierType
from asset_model import BasicDNSRelation
from asset_model import PrefDNSRelation
from asset_model import SourceProperty
from asset_model import DNSRecordProperty
from asset_store.repository.repository import Repository
from asset_store.types import Entity, Edge
from asset_store.events.events import Event

from . import __title__

HandlerCallback = Callable[[Repository, Entity, str, dns.rdata.Rdata], dict]

handlers: dict[Type[dns.rdata.Rdata], HandlerCallback] = {}


def add_source(store: Repository, o: Entity | Edge) -> Optional[Event]:
    if type(o) is Entity:
        return store.create_entity_property(
            o, SourceProperty(source=__title__, confidence=100))
    if type(o) is Edge:
        return store.create_edge_property(
            o, SourceProperty(source=__title__, confidence=100))


def dispatch(
        store: Repository,
        base: Entity,
        rdtype: str,
        rdata: Rdata
) -> dict:
    handler = handlers.get(type(rdata))
    if handler is None:
        return handle_default(store, base, rdtype, rdata)
    return handler(store, base, rdtype, rdata)


def handle_default(
        store: Repository,
        base: Entity,
        rdtype: str,
        rdata: Rdata
) -> list[Event]:
    data = {"value": rdata.to_text()}

    store.create_entity_property(
        base,
        DNSRecordProperty(
            "dns_record",
            data["value"],
            rrtype=rdata.rdtype,
            rrname=rdtype
        ))

    return data


def handle(rdtype: Type[dns.rdata.Rdata]):
    def decorator(func: HandlerCallback) -> HandlerCallback:
        handlers[rdtype] = func
        return func
    return decorator


@handle(dns.rdtypes.IN.A.A)
def handle_a(store, base, rdtype, rdata):
    data = IPAddress(rdata.address, IPAddressType.IPv4)
    ip = store.create_asset(data)
    add_source(store, ip)

    rel = store.create_relation(
        BasicDNSRelation(
            "dns_record",
            rdata.rdtype,
            rrname=rdtype),
        base,
        ip)
    add_source(store, rel)
    return data.to_dict()


@handle(dns.rdtypes.IN.AAAA.AAAA)
def handle_aaaa(store, base, rdtype, rdata):
    data = IPAddress(rdata.address, IPAddressType.IPv6)
    ip_entity = store.create_asset(data)
    add_source(store, ip_entity)

    rel = store.create_relation(
        BasicDNSRelation(
            "dns_record", rdata.rdtype,
            rrname=rdtype),
        base,
        ip_entity)
    add_source(store, rel)
    return data.to_dict()


@handle(dns.rdtypes.ANY.CNAME.CNAME)
def handle_cname(store, base, rdtype, rdata):
    data = FQDN(rdata.target.to_text(True))
    fqdn_entity = store.create_asset(data)
    add_source(store, fqdn_entity)

    rel = store.create_relation(
        BasicDNSRelation(
            "dns_record", rdata.rdtype,
            rrname=rdtype),
        base,
        fqdn_entity)
    add_source(store, rel)
    return data.to_dict()


@handle(dns.rdtypes.ANY.NS.NS)
def handle_ns(store, base, rdtype, rdata):
    data = FQDN(rdata.target.to_text(True))
    fqdn_entity = store.create_asset(data)
    add_source(store, fqdn_entity)

    rel = store.create_relation(
        BasicDNSRelation(
            "dns_record", rdata.rdtype,
            rrname=rdtype),
        base,
        fqdn_entity)
    add_source(store, rel)
    return data.to_dict()


@handle(dns.rdtypes.ANY.SOA.SOA)
def handle_soa(store, base, rdtype, rdata):

    def rname_to_email(rname: str) -> str:
        name = dns.name.from_text(rname)
        local_part = name.labels[0].decode()
        domain = ".".join(label.decode() for label in name.labels[1:])
        return f"{local_part}@{domain}"

    data = {"value": rdata.to_text()}

    mname_value = rdata.mname.to_text(True)
    mname = FQDN(mname_value)
    mname_entity = store.create_asset(mname)
    add_source(store, mname_entity)

    rname_value = rname_to_email(rdata.rname.to_text(True))
    rname = Identifier(
        rname_value,
        rname_value,
        type=IdentifierType.EmailAddress)
    rname_entity = store.create_asset(rname)
    add_source(store, rname_entity)

    extra = {
        "mname": mname_value,
        "rname": rname_value,
        "serial": rdata.serial,
        "refresh": rdata.refresh,
        "retry": rdata.retry,
        "expire": rdata.expire,
        "minimum": rdata.minimum
    }

    mname_rel = store.create_relation(
        BasicDNSRelation(
            "dns_record",
            rdata.rdtype,
            rrname=rdtype,
            extra=extra),
        base,
        mname_entity)
    add_source(store, mname_rel)

    rname_rel = store.create_relation(
        BasicDNSRelation(
            "dns_record",
            rdata.rdtype,
            rrname=rdtype,
            extra=extra),
        base,
        rname_entity)
    add_source(store, rname_rel)

    return data


@handle(dns.rdtypes.ANY.MX.MX)
def handle_mx(store, base, rdtype, rdata):
    data = FQDN(rdata.exchange.to_text(True))
    fqdn_entity = store.create_asset(data)
    add_source(store, fqdn_entity)

    rel = store.create_relation(
        PrefDNSRelation(
            "dns_record",
            preference=rdata.preference,
            rrtype=rdata.rdtype,
            rrname=rdtype),
        base,
        fqdn_entity)
    add_source(store, rel)
    return data.to_dict()


@handle(dns.rdtypes.ANY.TXT.TXT)
def handle_txt(store, base, rdtype, rdata):
    data = {"value": ''.join([s.decode('utf-8') for s in rdata.strings])}

    prop = store.create_entity_property(
        base,
        DNSRecordProperty(
            "dns_record",
            data["value"],
            rrtype=rdata.rdtype,
            rrname=rdtype
        ))
    add_source(store, prop)
    return data


@handle(dns.rdtypes.IN.SRV.SRV)
def handle_srv(store, base, rdtype, rdata):
    data = {"value": ''.join([s.decode('utf-8') for s in rdata.strings])}

    store.create_entity_property(
        base,
        DNSRecordProperty(
            "dns_record",
            data["value"],
            rrtype=rdata.rdtype,
            rrname=rdtype
        ))
    return data
