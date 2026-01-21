# Lack support for :
# - TLSCertificate -[subject_contact]-> ContactRecord
# - TLSCertificate -[issuer_contact]-> ContactRecord

from argparse import ArgumentParser
from asset_model import FQDN
from asset_model import URL
from asset_model import IPAddress
from asset_model import Identifier
from asset_model import SimpleRelation
from asset_store.types import Entity
import socket
import ssl
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.x509.oid import SubjectInformationAccessOID
from typing import Optional
from graphrecon_lib import Context

import certdump.lib as lib


def make_argument_parser() -> ArgumentParser:
    parser = ArgumentParser(
        description="Dump TLS certificate.",
        prog="certdump"
    )
    parser.add_argument("-d", "--domain",
                        help="the target domain",
                        required=True)
    return parser


def get_cert_chain(hostname: str):
    context = ssl.create_default_context()
    with socket.create_connection((hostname, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            return ssock.get_verified_chain()


def main():
    parser = make_argument_parser()

    with Context.from_argument_parser(parser) as ctx:

        base = ctx.db.create_asset(FQDN(ctx.config.domain))

        chain = get_cert_chain(ctx.config.domain)

        previous_cert = None

        for raw_cert in chain:
            cert, fmt = lib.load_certificate(raw_cert)

            cert_entity = ctx.db.create_entity(
                lib.make_certificate_entity(cert))

            if previous_cert is not None:
                ctx.db.create_relation(
                    SimpleRelation("issuing_certificate"),
                    previous_cert,
                    cert_entity)

            # handle CN subject
            CN_list = lib.handle_CN_subject(cert)
            for cn in CN_list:
                lib.store_cert_common_name(ctx, cert_entity, cn)

            # handle O subject
            O_list = lib.handle_O_subject(cert)
            for o in O_list:
                if cert_entity.asset.is_ca:
                    lib.store_cert_authority_org(ctx, cert_entity, o)
                else:
                    lib.store_domain_verified_for_org(ctx, base, o)
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
                if primary_org:
                    lib.store_org_org_unit_org(ctx, primary_org, ou)
                else:
                    if cert_entity.asset.is_ca:
                        lib.store_cert_authority_org(ctx, cert_entity, ou)
                    else:
                        lib.store_domain_verified_for_org(ctx, base, ou)

            # handle SAN names
            san_names = lib.make_san_entry(
                cert,
                x509.DNSName,
                FQDN,
                'from_text')
            for name in san_names:
                lib.store_cert_san_dns_name(ctx, cert_entity, name)
                for org in O_list:
                    lib.store_domain_verified_for_org(ctx, name, org)

            # handle SAN addresses
            san_addresses = lib.make_san_entry(
                cert,
                x509.IPAddress,
                IPAddress,
                'from_text')
            for addr in san_addresses:
                lib.store_cert_san_address(ctx, cert_entity, addr)

            # handle SAN emails
            san_emails = lib.make_san_entry(
                cert,
                x509.RFC822Name,
                Identifier,
                'from_email')
            for email in san_emails:
                lib.store_cert_san_email(ctx, cert_entity, email)

            # handle SAN URLs
            san_urls = lib.make_san_entry(
                cert,
                x509.UniformResourceIdentifier,
                URL,
                'from_text')
            for url in san_urls:
                lib.store_cert_san_url(ctx, cert_entity, url)

            # handle OCSP URL
            ocsp_url = lib.make_info_access_entry(
                cert,
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
                AuthorityInformationAccessOID.OCSP,
                URL,
                'from_text')
            if ocsp_url is not None:
                lib.store_cert_ocsp_server_url(ctx, cert_entity, ocsp_url)

            # handle issuing cert URL
            iss_cert_url = lib.make_info_access_entry(
                cert,
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
                AuthorityInformationAccessOID.CA_ISSUERS,
                URL,
                'from_text')
            if iss_cert_url is not None:
                lib.store_cert_issuing_certificate_url(
                    ctx,
                    cert_entity,
                    iss_cert_url)

            # handle CA repo URL
            ca_repo_url = lib.make_info_access_entry(
                cert,
                ExtensionOID.SUBJECT_INFORMATION_ACCESS,
                SubjectInformationAccessOID.CA_REPOSITORY,
                URL,
                'from_text')
            if ca_repo_url is not None:
                lib.store_cert_issuing_certificate_url(
                    ctx,
                    cert_entity,
                    ca_repo_url)

            previous_cert = cert_entity
