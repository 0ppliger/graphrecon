from asset_model import TLSCertificate, TLSKeyUsageType, TLSExtKeyUsageType
from asset_model import FQDN
from asset_model import Organization
from asset_model import IPAddress
from asset_model import Identifier
from asset_model import URL
from asset_model import AssetType, Asset
from asset_model import Relation
from asset_model import SimpleRelation
from asset_model import get_asset_by_type
from asset_store.types import Entity, Edge
from typing import Type, TypeVar, Optional
from cryptography import x509
from cryptography.x509 import Certificate
from cryptography.x509 import GeneralName
from cryptography.x509.oid import NameOID
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509 import ExtensionNotFound
from graphrecon_lib import Context

T = TypeVar("T")
A = TypeVar("A")
B = TypeVar("B")


def format_key_identifier(key_identifier: bytes) -> str:
    return ":".join(f"{b:02X}" for b in key_identifier)


def make_san_entry(
        cert: Certificate,
        in_type: GeneralName,
        out_type: Type[T],
        factory: str
) -> list[T]:
    san_oid = ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    try:
        san = cert.extensions.get_extension_for_oid(san_oid).value
    except Exception:
        return []

    san_names = san.get_values_for_type(in_type)

    factory = getattr(out_type, factory)

    l: list[Asset] = []
    for n in san_names:
        try:
            asset = factory(n)
            l.append(asset)
        except ValueError:
            continue

    return l


def make_info_access_entry(
        cert: Certificate,
        info_access_oid: ExtensionOID,
        in_type: GeneralName,
        out_type: Type[T],
        factory: str
) -> Optional[T]:
    if info_access_oid != ExtensionOID.AUTHORITY_INFORMATION_ACCESS \
       and info_access_oid != ExtensionOID.SUBJECT_INFORMATION_ACCESS:
        raise ValueError("info_access_oid must be AUTHORITY_INFORMATION_ACCESS or SUBJECT_INFORMATION_ACCESS")

    try:
        info_access = cert.extensions.get_extension_for_oid(info_access_oid).value
    except Exception:
        return None

    for desc in info_access:
        if desc.access_method == in_type:
            factory = getattr(out_type, factory)
            value = desc.access_location.value
            return factory(value)

    return None


def make_certificate_entity(cert: Certificate) -> Entity:
    sub_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(sub_attrs) < 1:
        sub_cn = ""
    else:
        sub_cn = sub_attrs[0].value

    iss_attrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(iss_attrs) < 1:
        iss_cn = ""
    else:
        iss_cn = iss_attrs[0].value

    key_usage = []
    try:
        _key_usage = cert.extensions\
                         .get_extension_for_oid(ExtensionOID.KEY_USAGE)\
                         .value
        if _key_usage.digital_signature:
            key_usage.append(TLSKeyUsageType.DigitalSignature)
        if _key_usage.content_commitment:
            key_usage.append(TLSKeyUsageType.ContentCommitment)
        if _key_usage.key_encipherment:
            key_usage.append(TLSKeyUsageType.KeyEncipherment)
        if _key_usage.data_encipherment:
            key_usage.append(TLSKeyUsageType.DataEncipherment)
        if _key_usage.key_agreement:
            key_usage.append(TLSKeyUsageType.KeyAgreement)
        if _key_usage.key_cert_sign:
            key_usage.append(TLSKeyUsageType.CertSign)
        if _key_usage.crl_sign:
            key_usage.append(TLSKeyUsageType.CRLSign)
        if _key_usage.key_agreement and _key_usage.encipher_only:
            key_usage.append(TLSKeyUsageType.EncipherOnly)
        if _key_usage.key_agreement and _key_usage.decipher_only:
            key_usage.append(TLSKeyUsageType.DecipherOnly)
    except ExtensionNotFound:
        pass

    # TODO: Not finished
    eku = []
    try:
        _eku = cert.extensions\
                   .get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)\
                   .value
        if ExtendedKeyUsageOID.CLIENT_AUTH in _eku:
            eku.append(TLSExtKeyUsageType.ClientAuth)
        if ExtendedKeyUsageOID.SERVER_AUTH in _eku:
            eku.append(TLSExtKeyUsageType.ServerAuth)
        if ExtendedKeyUsageOID.CODE_SIGNING in _eku:
            eku.append(TLSExtKeyUsageType.CodeSigning)
        if ExtendedKeyUsageOID.EMAIL_PROTECTION in _eku:
            eku.append(TLSExtKeyUsageType.EmailProtection)
        if ExtendedKeyUsageOID.IPSEC_IKE in _eku:
            eku.append(TLSExtKeyUsageType.IPSECEndSystem)
        if ExtendedKeyUsageOID.TIME_STAMPING in _eku:
            eku.append(TLSExtKeyUsageType.TimeStamping)
        if ExtendedKeyUsageOID.OCSP_SIGNING in _eku:
            eku.append(TLSExtKeyUsageType.OCSPSigning)
    except ExtensionNotFound:
        pass

    is_ca = False
    try:
        _bc = cert.extensions\
                  .get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)\
                  .value
        is_ca = _bc.ca
    except x509.ExtensionNotFound:
        pass

    cdp = []
    try:
        _cdp = cert.extensions\
                   .get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)\
                   .value
        cdp = [dp.full_name[0].value for dp in _cdp]
    except x509.ExtensionNotFound:
        pass

    try:
        _ski = cert.extensions\
            .get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)\
            .value.key_identifier
        ski = format_key_identifier(_ski)
    except x509.ExtensionNotFound:
        ski = ""

    try:
        _aki = cert.extensions\
            .get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)\
            .value.key_identifier
        aki = format_key_identifier(_aki)
    except x509.ExtensionNotFound:
        aki = ""

    cert = TLSCertificate(
        version                  = cert.version.value,
        serial_number            = str(cert.serial_number),
        subject_common_name      = sub_cn,
        issuer_common_name       = iss_cn,
        not_before               = cert.not_valid_before_utc.isoformat(),
        not_after                = cert.not_valid_after_utc.isoformat(),
        key_usage                = key_usage,
        ext_key_usage            = eku,
        signature_algorithm      = cert.signature_algorithm_oid._name,
        public_key_algorithm     = cert.public_key_algorithm_oid._name,
        is_ca                    = is_ca,
        crl_distribution_points  = cdp,
        subject_key_id           = ski,
        authority_key_id         = aki
    )

    return Entity(asset=cert)

def load_certificate(cert_bytes: bytes) -> tuple[x509.Certificate, str]:
    try:
        return (x509.load_pem_x509_certificate(cert_bytes), "PEM")
    except ValueError:
        pass

    try:
        return (x509.load_der_x509_certificate(cert_bytes), "DER")
    except ValueError:
        pass

    raise ValueError("Input is not a valid PEM or DER X.509 certificate")

def _get_entity(o: Entity | T, asset_type: AssetType) -> Entity:
    asset_cls = get_asset_by_type(asset_type)
    if isinstance(o, asset_cls):
        return Entity(asset=o)
    elif isinstance(o, Entity) and o.asset.asset_type == asset_type:
        return o
    else:
        raise ValueError(f"param must be a '{asset_type}' or a derived entity")
    
def _store(ctx: Context, a: Entity | A, a_type: AssetType, b: Entity | B, b_type: AssetType, rel: Relation) -> tuple[Entity, Edge, Entity]:
    a_entity = ctx.db.create_entity(_get_entity(a, a_type))
    b_entity = ctx.db.create_entity(_get_entity(b, b_type))
    rel = ctx.db.create_relation(rel, a_entity, b_entity)
    return (a_entity, rel, b_entity)
    
# STORES ---

def store_cert_common_name(
        ctx: Context,
        cert: Entity | TLSCertificate,
        fqdn: Entity | FQDN
) -> tuple[Entity, Edge, Entity]:
    return _store(ctx,
                  cert, AssetType.TLSCertificate,
                  fqdn, AssetType.FQDN,
                  SimpleRelation("common_name"))

def store_domain_verified_for_org(ctx: Context, fqdn: Entity | FQDN, org: Entity | Organization) -> tuple[Entity, Edge, Entity]:
    return _store(ctx,
                  fqdn, AssetType.FQDN,
                  org, AssetType.Organization,
                  SimpleRelation("verified_for"))

def store_cert_authority_org(ctx: Context, cert: Entity | TLSCertificate, org: Entity | Organization) -> tuple[Entity, Edge, Entity]:
    return _store(ctx,
                  cert, AssetType.TLSCertificate,
                  org, AssetType.Organization,
                  SimpleRelation("certificate_authority"))

def store_org_org_unit_org(ctx: Context, org: Entity | Organization, org_unit: Entity | Organization) -> tuple[Entity, Edge, Entity]:
    return _store(ctx,
                  org, AssetType.Organization,
                  org_unit, AssetType.Organization,
                  SimpleRelation("org_unit"))

def store_cert_san_dns_name(
        ctx: Context,
        cert: Entity | TLSCertificate,
        fqdn: Entity | FQDN
) -> tuple[Entity, Edge, Entity]:
    return _store(ctx,
                  cert, AssetType.TLSCertificate,
                  fqdn, AssetType.FQDN,
                  SimpleRelation("san_dns_name"))

def store_cert_san_address(
        ctx: Context,
        cert: Entity | TLSCertificate,
        addr: Entity | IPAddress
) -> tuple[Entity, Edge, Entity]:
    return _store(ctx,
                  cert, AssetType.TLSCertificate,
                  addr, AssetType.IPAddress,
                  SimpleRelation("san_ip_address"))

def store_cert_san_email(
        ctx: Context,
        cert: Entity | TLSCertificate,
        email: Entity | Identifier
) -> tuple[Entity, Edge, Entity]:
    return _store(ctx,
                  cert, AssetType.TLSCertificate,
                  email, AssetType.Identifier,
                  SimpleRelation("san_email_address"))

def store_cert_san_url(
        ctx: Context,
        cert: Entity | TLSCertificate,
        url: Entity | URL
) -> tuple[Entity, Edge, Entity]:
    return _store(ctx,
                  cert, AssetType.TLSCertificate,
                  url, AssetType.URL,
                  SimpleRelation("san_url"))

def store_cert_ocsp_server_url(
        ctx: Context,
        cert: Entity | TLSCertificate,
        url: Entity | URL
) -> tuple[Entity, Edge, Entity]:
    return _store(ctx,
                  cert, AssetType.TLSCertificate,
                  url, AssetType.URL,
                  SimpleRelation("ocsp_server"))

def store_cert_issuing_certificate_url(
        ctx: Context,
        cert: Entity | TLSCertificate,
        url: Entity | URL
) -> tuple[Entity, Edge, Entity]:
        return _store(ctx,
                  cert, AssetType.TLSCertificate,
                  url, AssetType.URL,
                  SimpleRelation("issuing_certificate_url"))

# HANDLERS ---

def handle_CN_subject(cert: Certificate) -> list[FQDN]:
    common_names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(common_names) == 0:
        return []

    l = []
    for cn in common_names:
        try:
            fqdn = FQDN.from_text(name.value)
            l.append(fqdn)
        except:
            continue
        
    return l

def handle_O_subject(cert: Certificate) -> list[Organization]:
    org_names = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    if len(org_names) == 0:
        return []

    return [Organization(name.value, name.value) for name in org_names]

def handle_OU_subject(cert: Certificate) -> list[Organization]:
    ou_names = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
    if len(ou_names) == 0:
        return []

    return [Organization(name.value, name.value) for name in ou_names]
