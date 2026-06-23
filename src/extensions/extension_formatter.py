import cryptography.x509 as x509
from cryptography.x509.extensions import (
    AuthorityInformationAccess,
    CRLNumber, 
    AuthorityKeyIdentifier, 
    SubjectKeyIdentifier, 
    SubjectInformationAccess, 
    BasicConstraints, 
    DeltaCRLIndicator, 
    CRLDistributionPoints, 
    FreshestCRL, 
    DistributionPoint, 
    PolicyConstraints, 
    CertificatePolicies, 
    PolicyInformation, 
    ExtendedKeyUsage, 
    OCSPNoCheck, 
    PrecertPoison, 
    TLSFeature, 
    InhibitAnyPolicy, 
    KeyUsage, 
    PrivateKeyUsagePeriod, 
    NameConstraints, 
    SubjectAlternativeName, 
    IssuerAlternativeName, 
    CertificateIssuer, 
    CRLReason, 
    InvalidityDate, 
    PrecertificateSignedCertificateTimestamps, 
    SignedCertificateTimestamps, 
    OCSPNonce,
    OCSPAcceptableResponses, 
    IssuingDistributionPoint, 
    MSCertificateTemplate, 
    ProfessionInfo, 
    Admissions, 
    UnrecognizedExtension,
)
import codecs
import datetime

def bytes_to_hex(bytes_data: bytes | None) -> str | None:
    if bytes_data is None:
        return None
    return bytes_data.hex(':').upper()

def bytes_to_hex_without_sep(bytes_data: bytes | None) -> str | None:
    if bytes_data is None:
        return None
    return bytes_data.hex().upper()

def format_props_to_str(
        *values: tuple[str, bool | str | int | None | list], 
        sep: str = ', ', 
        line_sep: str = '\n', 
        assigment: str = ": ", 
        indent: int = 0,
        hide_false: bool = False
) -> str:
    booleans = []
    lines = []
    for key, value in values:
        if not value:
            continue
        if isinstance(value, list):
            values_str = sep.join([str(v) for v in value])
            lines.append(f"{key}{assigment}{values_str}")
        if isinstance(value, bool):
            if hide_false and not value:
                continue
            booleans.append(key)
        else:
            lines.append(f"{key}{assigment}{value}")
    lines.append(sep.join(booleans))
    result_str = line_sep.join([f"{' ' * indent}{line}" for line in lines])
    return result_str

def format_names(names: list[x509.GeneralName] | None, sep: str = '\n', indent: int = 0, new_line: bool = True) -> str | None:
    if names is None:
        return None
    result_str = f'{sep.join([f"{' ' * indent}{name.value}" for name in names])}'
    if new_line:
        result_str = sep + result_str
    return result_str

def format_san_names(ex: x509.SubjectAlternativeName | x509.IssuerAlternativeName | x509.CertificateIssuer, sep: str = ", ") -> str:
    return sep.join(get_san_names(ex))

def format_object_identifiers(oids: list[x509.ObjectIdentifier] | None, sep: str = '\n', indent: int = 0):
    if oids is None:
        return None
    oid_strings = []
    for oid in oids:
        if oid is None:
            continue
        if oid._name == "Unknown OID":
            oid_strings.append(f"{' ' * indent}{oid.dotted_string}")
        else:
            oid_strings.append(f"{' ' * indent}{oid._name}")
    return sep.join(oid_strings)

def format_object_identifier(oid: x509.ObjectIdentifier | None, indent: int = 0):
    if oid is None:
        return None
    return f"{' ' * indent}{oid._name if oid._name != 'Unknown OID' else oid.dotted_string}"

def basic_constraints_format(basic_constraints: BasicConstraints) -> str:
    ca_str = "CA:TRUE" if basic_constraints.ca else "CA:FALSE"
    return format_props_to_str(
        (ca_str, True), 
        ("Path length", basic_constraints.path_length)
    )

def format_distribution_point(distribution_point: DistributionPoint, indent: int = 0):
    full_name = format_names(distribution_point.full_name, indent=indent+1)
    crl_issuer = format_names(distribution_point.crl_issuer, indent=indent+1)
    relative_name = distribution_point.relative_name.rfc4514_string() if distribution_point.relative_name else None
    reasons = ", ".join([str(reason) for reason in distribution_point.reasons]) if distribution_point.reasons else None
    return format_props_to_str(
        ("Full name", full_name), 
        ("CRL issuer", crl_issuer), 
        ("Relative name", relative_name), 
        ("Reasons", reasons),
        indent=indent
    )

def format_issuing_distribution_point(issuing_distribution_point: IssuingDistributionPoint, indent: int = 0):
    full_name = format_names(issuing_distribution_point.full_name, indent=indent+1)
    relative_name = issuing_distribution_point.relative_name.rfc4514_string() if issuing_distribution_point.relative_name else None
    only_some_reasons = ", ".join([str(reason) for reason in issuing_distribution_point.only_some_reasons]) if issuing_distribution_point.only_some_reasons else None
    return format_props_to_str(
        ("Full Name", full_name),
        ("Only some reasons", only_some_reasons),
        ("Relative name", relative_name),
        ("Only contains user certs", issuing_distribution_point.only_contains_user_certs),
        ("Only contains attribute certs", issuing_distribution_point.only_contains_attribute_certs),
        ("Inderect CRL", issuing_distribution_point.indirect_crl),
        ("Only contains CA certs", issuing_distribution_point.only_contains_ca_certs),
        indent=indent
    )

def format_policy_information(policy_information: PolicyInformation, indent: int = 0) -> str:
    qualifiers = None
    if isinstance(policy_information.policy_qualifiers, str):
        qualifiers = policy_information.policy_qualifiers
    elif isinstance(policy_information.policy_qualifiers, x509.UserNotice):
        qualifiers = format_props_to_str(("explicit_text", policy_information.policy_qualifiers.explicit_text), indent=indent+1)
        if policy_information.policy_qualifiers.notice_reference:
            qualifiers += format_props_to_str(
                ("Organization", policy_information.policy_qualifiers.notice_reference.organization),
                ("Notice numbers", policy_information.policy_qualifiers.notice_reference.notice_numbers),
                indent=indent+1
            )
    return format_props_to_str(
        ("Policy identifier", policy_information.policy_identifier.dotted_string),
        ("User notice", qualifiers),
        indent=indent
    )

def format_key_usage(key_usage: KeyUsage):
    try:
        encipher_only=key_usage.encipher_only
        decipher_only=key_usage.decipher_only
    except ValueError:
        encipher_only=False
        decipher_only=False
    return format_props_to_str(
        ("DigitalSignature", key_usage.digital_signature),
        ("ContentCommitment", key_usage.content_commitment),
        ("KeyEncipherment", key_usage.key_encipherment),
        ("DataEncipherment", key_usage.data_encipherment),
        ("KeyAgreement", key_usage.key_agreement),
        ("KeyCertSign", key_usage.key_cert_sign),
        ("CRLSign", key_usage.crl_sign),
        ("EncipherOnly", encipher_only),
        ("DecipherOnly", decipher_only),
        hide_false=True
    )

def get_san_names(ex: x509.SubjectAlternativeName | x509.IssuerAlternativeName | x509.CertificateIssuer) -> list[str]:
    names_lst = []
    for name in ex:
        match name:
            case x509.DNSName():
                names_lst.append(f"DNS:{name.value}")
            case x509.IPAddress():
                names_lst.append(f"IP Address:{name.value}")
            case x509.RFC822Name():
                names_lst.append(f"Email:{name.value}")
            case x509.UniformResourceIdentifier():
                names_lst.append(f"URI:{name.value}")
            case x509.DirectoryName():
                names_lst.append(f"DirName:{name.value.rfc4514_string()}")
            case x509.RegisteredID():
                names_lst.append(f"RID:{name.value.dotted_string}")
            case x509.OtherName():
                names_lst.append(f"OtherName:{name.value.hex()}")
    return sorted(names_lst)

def format_naming_authority(naming_authority: x509.NamingAuthority | None, indent: int = 0):
    if naming_authority is None:
        return None
    oid = format_object_identifier(naming_authority.id, indent=indent+1)
    return format_props_to_str(
        ("Id", oid),
        ("URL", naming_authority.url),
        ("Text", naming_authority.text),
        indent=indent
    )

def format_profession_info(profession_info: ProfessionInfo, indent: int = 0):
    naming_authority = format_naming_authority(profession_info.naming_authority)
    profession_items = ", ".join(profession_info.profession_items)
    profession_oids = format_object_identifiers(profession_info.profession_oids, indent=indent + 1)
    registration_number = profession_info.registration_number
    add_profession_info = bytes_to_hex(profession_info.add_profession_info) if profession_info.add_profession_info else None
    return (
        format_props_to_str(
            ("Namin authority", naming_authority),
            ("Profession items", profession_items),
            ("Profession OIDs", profession_oids),
            ("Registration number", registration_number),
            ("Add profession info", add_profession_info),
            indent=indent
        )
    )

def format_admissions(admissions: Admissions, indent: int = 0) -> str:
    authority = admissions.authority.value if admissions.authority else None
    admissions_lst = []
    for admission in admissions:
        admission_authority = admission.authority.value if admission.authority else None
        naming_authority =  format_naming_authority(admission.naming_authority)
        profession_info = "\n".join(f"{format_profession_info(admission.profession_info, indent=indent+1)}") if admission.profession_info else None
        admissions_lst.append(
            format_props_to_str(
                ("Addmission authority", admission_authority),
                ("Naming authority", naming_authority),
                ("Profession info", profession_info),
                indent=indent+1
            )
        )
    return format_props_to_str(
        ("authority", authority),
        ("admissions", admissions_lst),
        indent=indent
    )

def extensions_to_dict(extensions: x509.Extensions) -> dict[str, str]:
    extension: x509.Extension
    extensions_dict = {}
    for extension in extensions:
        name, value = extension_value_to_tuple(extension.value)
        if value is None:
            value = ""
        # value += f", critical={extension.critical}"
        extensions_dict[name] = value
    return extensions_dict

def format_unrecognized_custom(ex: UnrecognizedExtension) -> tuple[str, str | None]:
    oid = ex.oid.dotted_string
    val = ex.value
    match oid:
        # SafeTech использует для передачи шаблона сертификата
        case "1.3.6.1.4.1.311.20.2":
            bom = codecs.BOM_UTF16_BE
            return "msCertificateTemplate", val.removeprefix(bom).decode('utf-16-be')
        case _:
            return ex.oid.dotted_string, bytes_to_hex_without_sep(val)
        
def format_access_descriptions(access_descriptions: x509.SubjectInformationAccess | x509.AuthorityInformationAccess, indent: int = 0):
    access_list = []
    for access in access_descriptions:
        access_method = format_object_identifier(access.access_method)
        if access_method is None:
            # Такого не должно быть
            continue
        access_list.append(format_props_to_str(
            (access_method, access.access_location.value)
        ))
    return "\n".join(access_list)

def format_date(date: datetime.datetime | None) -> str | None:
    if date is None:
        return None
    return date.isoformat()

def format_scts(scts: list[x509.certificate_transparency.SignedCertificateTimestamp]):
    formatted = []
    for sct in scts:
        formatted.append(format_props_to_str(
            ("Version", str(sct.version)),
            ("Timestamp", format_date(sct.timestamp)),
            ("Log ID", bytes_to_hex(sct.log_id)),
            ("Signature", bytes_to_hex(sct.signature)),
            ("Extensions", bytes_to_hex(sct.extension_bytes))
        ))

    return "\n".join(formatted)

def extension_value_to_tuple(ex: x509.ExtensionType) -> tuple[str, str | None]:
    match ex:
        case CRLNumber():
            return "crlNumber", str(ex.crl_number)
        case AuthorityKeyIdentifier():
            return "authorityKeyIdentifier", bytes_to_hex(ex.key_identifier)
        case SubjectKeyIdentifier():
            return "subjectKeyIdentifier", bytes_to_hex(ex.key_identifier)
        case AuthorityInformationAccess():
            return "authorityInfoAccess", format_access_descriptions(ex)
        case SubjectInformationAccess():
            return "subjectInfoAccess", format_access_descriptions(ex)
        case BasicConstraints():
            return "basicConstraints", basic_constraints_format(ex)
        case DeltaCRLIndicator():
            return "deltaCRLIndicator", str(ex.crl_number)
        case CRLDistributionPoints():
            return "crlDistributionPoints", "\n".join([format_distribution_point(dp) for dp in ex])
        case FreshestCRL():
            return "freshestCRL", "\n".join([format_distribution_point(dp) for dp in ex])
        case PolicyConstraints():
            return "policyConstraints", format_props_to_str(("require_explicit_policy", ex.require_explicit_policy), ("ninhibit_policy_mapping", ex.inhibit_policy_mapping))
        case CertificatePolicies():
            return "certificatePolicies", "\n".join([format_policy_information(policy) for policy in ex])
        case ExtendedKeyUsage():
            return "extendedKeyUsage", format_object_identifiers(list(ex), sep=", ")
        case OCSPNoCheck():
            return "ocspNoCheck", None
        case PrecertPoison():
            return "precertPoison", None
        case TLSFeature():
            return "tlsFeature", ", ".join([str(feature) for feature in ex])
        case InhibitAnyPolicy():
            return "inhibitAnyPolicy", str(ex.skip_certs)
        case KeyUsage():
            return "keyUsage", format_key_usage(ex)
        case PrivateKeyUsagePeriod():
            return "privateKeyUsagePeriod", format_props_to_str(("not_before", format_date(ex.not_before)), ("not_after", format_date(ex.not_after)))
        case NameConstraints():
            return "nameConstraints", format_props_to_str(("permitted_subtrees", format_names(ex.permitted_subtrees, indent=1)), ("nexcluded_subtrees", format_names(ex.excluded_subtrees, indent=1)))
        case SubjectAlternativeName():
            return "subjectAltName", format_san_names(ex)
        case IssuerAlternativeName():
            return "issuerAltName", format_san_names(ex)
        case CertificateIssuer():
            return "certificateIssuer", format_san_names(ex)
        case CRLReason():
            return "crlReason", str(ex.reason)
        case InvalidityDate():
            return "invalidityDate", format_date(ex.invalidity_date)
        case PrecertificateSignedCertificateTimestamps():
            return "ct_precert_scts", format_scts(list(ex))
        case SignedCertificateTimestamps():
            return "ct_cert_scts", format_scts(list(ex))
        case OCSPNonce():
            return "ocspNonce", bytes_to_hex(ex.nonce)
        case OCSPAcceptableResponses():
            return "ocspAcceptableResponses", format_object_identifiers(list(ex))
        case IssuingDistributionPoint():
            return "issuingDistributionPoint", format_issuing_distribution_point(ex)
        case MSCertificateTemplate():
            return "msCertificateTemplate", format_props_to_str(("template_id", format_object_identifier(ex.template_id)), ("nmajor_version", ex.major_version), ("nminor_version", ex.minor_version))
        case Admissions():
            return "ddmissions", format_admissions(ex)
        case UnrecognizedExtension():
            return format_unrecognized_custom(ex)
        case _:
            return ex.oid.dotted_string, None
