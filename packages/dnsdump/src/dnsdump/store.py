from typing import Type, Callable
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
from asset_model import BasicDNSRelation, RRHeader
from asset_model import PrefDNSRelation
from asset_model import SourceProperty
from asset_model import DNSRecordProperty

from oam_client import BrokerClient
from oam_client.messages import Entity, Edge, EntityTag, EdgeTag

from . import __title__

HandlerCallback = Callable[[BrokerClient, Entity, str, dns.rdata.Rdata], dict]

handlers: dict[Type[dns.rdata.Rdata], HandlerCallback] = {}


def add_source(store: BrokerClient, o: Entity | Edge) -> EntityTag | EdgeTag:
    if type(o) is Entity:
        return store.create_entity_tag(
            SourceProperty(source=__title__, confidence=100), o.id)
    if type(o) is Edge:
        return store.create_edge_tag(
            SourceProperty(source=__title__, confidence=100), o.id)


def dispatch(
        store: BrokerClient,
        base: Entity,
        rdtype: str,
        rdata: Rdata
) -> dict:
    handler = handlers.get(type(rdata))
    if handler is None:
        return handle_default(store, base, rdtype, rdata)
    return handler(store, base, rdtype, rdata)


def handle_default(
        store: BrokerClient,
        base: Entity,
        rdtype: str,
        rdata: Rdata
) -> dict:
    data = {"value": rdata.to_text()}

    store.create_entity_tag(
        DNSRecordProperty(
            "dns_record",
            data["value"],
            header=RRHeader(
                rrtype=rdata.rdtype,
                rrname=rdtype
            )),
        base.id)

    return data


def handle(rdtype: Type[dns.rdata.Rdata]):
    def decorator(func: HandlerCallback) -> HandlerCallback:
        handlers[rdtype] = func
        return func
    return decorator


@handle(dns.rdtypes.IN.A.A)
def handle_a(store, base, rdtype, rdata):
    data = IPAddress(rdata.address, IPAddressType.IPv4)
    ip = store.create_entity(data)
    add_source(store, ip)

    rel = store.create_edge(
        BasicDNSRelation(
            "dns_record",
            header=RRHeader(
                rrtype=rdata.rdtype,
                rrname=rdtype,
            )),
        base.id,
        ip.id)
    add_source(store, rel)
    return data.to_dict()


@handle(dns.rdtypes.IN.AAAA.AAAA)
def handle_aaaa(store, base, rdtype, rdata):
    data = IPAddress(rdata.address, IPAddressType.IPv6)
    ip_entity = store.create_entity(data)
    add_source(store, ip_entity)

    rel = store.create_edge(
        BasicDNSRelation(
            "dns_record",
            header=RRHeader(
                rrtype=rdata.rdtype,
                rrname=rdtype,
            )),
        base.id,
        ip_entity.id)
    add_source(store, rel)
    return data.to_dict()


@handle(dns.rdtypes.ANY.CNAME.CNAME)
def handle_cname(store, base, rdtype, rdata):
    data = FQDN(rdata.target.to_text(True))
    fqdn_entity = store.create_entity(data)
    add_source(store, fqdn_entity)

    rel = store.create_edge(
        BasicDNSRelation(
            "dns_record",
            header=RRHeader(
                rrtype=rdata.rdtype,
                rrname=rdtype,
            )),
        base.id,
        fqdn_entity.id)
    add_source(store, rel)
    return data.to_dict()


@handle(dns.rdtypes.ANY.NS.NS)
def handle_ns(store, base, rdtype, rdata):
    data = FQDN(rdata.target.to_text(True))
    fqdn_entity = store.create_entity(data)
    add_source(store, fqdn_entity)

    rel = store.create_edge(
        BasicDNSRelation(
            "dns_record",
            header=RRHeader(
                rrtype=rdata.rdtype,
                rrname=rdtype,
            )),
        base.id,
        fqdn_entity.id)
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
    mname_entity = store.create_entity(mname)
    add_source(store, mname_entity)

    rname_value = rname_to_email(rdata.rname.to_text(True))
    rname = Identifier(
        rname_value,
        rname_value,
        type=IdentifierType.EmailAddress)
    rname_entity = store.create_entity(rname)
    add_source(store, rname_entity)

    mname_rel = store.create_edge(
        BasicDNSRelation(
            "dns_record",
            header=RRHeader(
                rrtype=rdata.rdtype,
                rrname=rdtype,
            )),
        base.id,
        mname_entity.id)
    add_source(store, mname_rel)

    rname_rel = store.create_edge(
        BasicDNSRelation(
            "dns_record",
            header=RRHeader(
                rrtype=rdata.rdtype,
                rrname=rdtype,
            )),
        base.id,
        rname_entity.id)
    add_source(store, rname_rel)

    return data


@handle(dns.rdtypes.ANY.MX.MX)
def handle_mx(store, base, rdtype, rdata):
    data = FQDN(rdata.exchange.to_text(True))
    fqdn_entity = store.create_entity(data)
    add_source(store, fqdn_entity)

    rel = store.create_edge(
        PrefDNSRelation(
            "dns_record",
            preference=rdata.preference,
            header=RRHeader(
                rrtype=rdata.rdtype,
                rrname=rdtype,
            )),
        base.id,
        fqdn_entity.id)
    add_source(store, rel)
    return data.to_dict()


@handle(dns.rdtypes.ANY.TXT.TXT)
def handle_txt(store, base, rdtype, rdata):
    data = {"value": ''.join([s.decode('utf-8') for s in rdata.strings])}

    prop = store.create_entity_tag(
        DNSRecordProperty(
            "dns_record",
            data["value"],
            header=RRHeader(
                rrtype=rdata.rdtype,
                rrname=rdtype,
            )
        ),
        base.id)
    add_source(store, prop)
    return data


@handle(dns.rdtypes.IN.SRV.SRV)
def handle_srv(store, base, rdtype, rdata):
    data = {"value": ''.join([s.decode('utf-8') for s in rdata.strings])}

    store.create_entity_tag(
        DNSRecordProperty(
            "dns_record",
            data["value"],
            header=RRHeader(
                rrtype=rdata.rdtype,
                rrname=rdtype,
            )),
        base.id)
    return data
