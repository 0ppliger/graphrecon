from asset_model import FQDN
from asset_model import URL
from asset_model import IPAddress
from asset_model import Identifier
from asset_model import SimpleRelation
from oam_client import BrokerClient
from oam_client.messages import Entity
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.x509.oid import SubjectInformationAccessOID
from typing import Optional, Callable
import certdump.lib as lib

from .core import get_cert_chain


class DumpCertificateCommand:

    IS_ASYNC: bool = False

    domain: str
    store: BrokerClient
    chain: list[x509.Certificate]
    on_success: Callable[[str, str], None]

    def __init__(
            self,
            domain: str,
            store: BrokerClient,
            on_success: Callable[[str, str], None]
    ):
        self.domain = domain
        self.store = store

        _chain = get_cert_chain(self.domain)

        self.chain = []
        for der in _chain:
            cert, _ = lib.load_certificate(der)
            self.chain.append(cert)

        self.on_success = on_success

    def run(self):
        base = self.store.create_entity(FQDN(self.domain))

        previous_cert = None

        for cert in self.chain:

            cert_entity = self.store.create_entity(
                lib.make_certificate_entity(cert))

            if previous_cert is not None:
                self.store.create_edge(
                    SimpleRelation("issuing_certificate"),
                    previous_cert.id,
                    cert_entity.id)

            # handle CN subject
            CN_list = lib.handle_CN_subject(cert)
            for cn in CN_list:
                lib.store_cert_common_name(
                    self.store, cert_entity, cn)
                self.on_success("CN", cn.to_json())

            # handle O subject
            O_list = lib.handle_O_subject(cert)
            for o in O_list:
                self.on_success("O", o.to_json())
                if cert_entity.asset.is_ca:
                    lib.store_cert_authority_org(
                        self.store, cert_entity, o)
                else:
                    lib.store_domain_verified_for_org(
                        self.store, base, o)
            # In case there is multiple "O", they are all verified_for the CN
            # and SAN domains, but only the first one is use for other
            # operations to avoid polluting the graph.
            primary_org: Optional[Entity]
            if len(O_list) > 0:
                [primary_org, *_] = O_list
            else:
                primary_org = None

            # handle OU subject
            OU_list = lib.handle_OU_subject(cert)
            for ou in OU_list:
                self.on_success("OU", ou.to_json())
                if primary_org:
                    lib.store_org_org_unit_org(self.store, primary_org, ou)
                else:
                    if cert_entity.asset.is_ca:
                        lib.store_cert_authority_org(
                            self.store, cert_entity, ou)
                    else:
                        lib.store_domain_verified_for_org(
                            self.store, base, ou)

            # handle SAN names
            san_names = lib.make_san_entry(
                cert, x509.DNSName, FQDN, 'from_text')
            for name in san_names:
                self.on_success("SAN", name.to_json())
                lib.store_cert_san_dns_name(
                    self.store, cert_entity, name)
                for org in O_list:
                    lib.store_domain_verified_for_org(
                        self.store, name, org)

            # handle SAN addresses
            san_addresses = lib.make_san_entry(
                cert, x509.IPAddress, IPAddress, 'from_text')
            for addr in san_addresses:
                self.on_success("SAN", addr.to_json())
                lib.store_cert_san_address(self.store, cert_entity, addr)

            # handle SAN emails
            san_emails = lib.make_san_entry(
                cert, x509.RFC822Name, Identifier, 'from_email')
            for email in san_emails:
                self.on_success("SAN", email.to_json())
                lib.store_cert_san_email(self.store, cert_entity, email)

            # handle SAN URLs
            san_urls = lib.make_san_entry(
                cert, x509.UniformResourceIdentifier, URL, 'from_text')
            for url in san_urls:
                self.on_success("SAN", url.to_json())
                lib.store_cert_san_url(self.store, cert_entity, url)

            # handle OCSP URL
            ocsp_url = lib.make_info_access_entry(
                cert, ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
                AuthorityInformationAccessOID.OCSP, URL, 'from_text')
            if ocsp_url is not None:
                self.on_success("OCSP", ocsp_url.to_json())
                lib.store_cert_ocsp_server_url(
                    self.store, cert_entity, ocsp_url)

            # handle issuing cert URL
            iss_cert_url = lib.make_info_access_entry(
                cert, ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
                AuthorityInformationAccessOID.CA_ISSUERS, URL, 'from_text')
            if iss_cert_url is not None:
                self.on_success("ISS CERT", iss_cert_url.to_json())
                lib.store_cert_issuing_certificate_url(
                    self.store, cert_entity, iss_cert_url)

            # handle CA repo URL
            ca_repo_url = lib.make_info_access_entry(
                cert, ExtensionOID.SUBJECT_INFORMATION_ACCESS,
                SubjectInformationAccessOID.CA_REPOSITORY, URL, 'from_text')
            if ca_repo_url is not None:
                self.on_success("CA REPO", ca_repo_url.to_json())
                lib.store_cert_issuing_certificate_url(
                    self.store, cert_entity, ca_repo_url)

            previous_cert = cert_entity
