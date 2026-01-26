from dns.name import Name
from asset_model import FQDN
from asset_model import SimpleRelation
from asset_store.repository.repository import Repository
from apex.core import is_apex


def store_fqdn(store: Repository, domain: Name):
    child = store.create_asset(FQDN(domain.to_text(True)))
    if is_apex(domain):
        return
    domain = domain.parent()
    parent = store.create_asset(FQDN(domain.to_text(True)))
    store.create_relation(SimpleRelation("node"), parent, child)
    store_fqdn(store, domain)
