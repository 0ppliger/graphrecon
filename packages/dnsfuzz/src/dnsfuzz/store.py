from dns.name import Name
from asset_model import FQDN
from asset_model import SimpleRelation
from oam_client import BrokerClient
from apex.core import is_apex

__parents: set[Name] = set()


def store_fqdn(store: BrokerClient, domain: Name):
    if domain in __parents:
        return

    child = store.create_entity(FQDN(domain.to_text(True)))
    if is_apex(domain):
        return

    domain = domain.parent()
    if domain in __parents:
        return

    __parents.add(domain)
    parent = store.create_entity(FQDN(domain.to_text(True)))
    store.create_edge(SimpleRelation("node"), parent.id, child.id)
    store_fqdn(store, domain)
