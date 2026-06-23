import typing
import datetime
import collections
import hashlib

from cryptography import x509 
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, dsa, ec, types
from cryptography.utils import int_to_bytes
from enum import Enum
from pydantic import BaseModel
from src.extensions.extension_formatter import extensions_to_dict, get_san_names
from src.extensions import choices


GostAlgInfo = collections.namedtuple("GostAlgInfo", "sig_alg key_size")
PublicKeyInfo = collections.namedtuple("PublicKeyInfo", "type size pk_str rsa_n modulus_sha256")

gosts = {
    "1.2.643.2.2.19": GostAlgInfo("ГОСТ Р 34.10-2001", 256),
    "1.2.643.7.1.1.1.1": GostAlgInfo("ГОСТ Р 34.10-2012", 256),
    "1.2.643.7.1.1.1.2": GostAlgInfo("ГОСТ Р 34.10-2012", 512),
}

class ModulusMismatch(ValueError):
    "Модулус в запросе, закрытом ключе или открытом не совпадают"
    pass

class PrivateKeyInfo(BaseModel):
    rsa_n: int | None
    p_type: KeyType
    p_size: int
    raw: str

class PrivateKeyEncrypted(BaseModel):
    """Для записи зашифрованного приватного ключа в базу данных"""
    key_enc: str
    ciphertext: str
    nonce: str
    tag: str

class CertificateState(str, Enum):
    """Статус сертификата"""
    
    ACTIVE = "Active"
    EXPIRED = "Expired"
    REVOKED = "Revoked"
    RESERVED = "Reserved"
    PENDING = "Pending"
    RESTRICTED = "Restricted"
    
class CertificateRenewState(str, Enum):
    """Статус обновления сертификата"""
    
    REISSUED = "Reissued"
    RENEW = "Renew"
    CANCELED = "Canceled"

class KeyType(str, Enum):
    """Key types"""
    
    RSA = "RSA"
    DSA = "DSA"
    EC = "EC"
    NONE = "None"

class CertificateInfo(BaseModel):
    """Данные полученные из сертификата"""
    serial_number: str
    not_after: datetime.datetime
    not_before: datetime.datetime
    version: int
    public_key: str | None
    public_key_type : KeyType | None
    public_key_size: int | None
    digest_sha256: str
    modulus_sha256: str
    issuer_kwargs: dict[str, str]
    issuer: str
    state: CertificateState
    subject_key_identifier: str
    subject_kwargs: dict[str, str]
    subject: str
    subject_alt_name: list[str]
    subject_alt_name_sha256: str
    certificate: str
    common_name: str
    authority_key_identifier: str
    extentions: dict[str, str]
    renew_state: CertificateRenewState
    signature_algorithm: str
    certificate_kwargs: dict[str, str]
    rsa_n: int | None

def hash_list(strings: list):
    key = "acme"
    hash = hashlib.blake2s()
    for s in strings:
        hash.update(
            hashlib.blake2s((key + s).encode('utf-8')).digest()
        )
    return hash.hexdigest()

def rfc4514_string_to_dict(rfc4514_string: str) -> dict[str, str]:
    result = {}
    for component in rfc4514_string.split(","):
        try:
            key, value = component.split("=", 1)
            result[key.strip()] = value.strip()
        except ValueError:
            # Если разделение по "=" не удалось, пропускаем этот компонент
            continue
    return result

def rsa_n_to_modulus_sha256(rsa_n: int) -> str:
    return hashlib.sha256(int_to_bytes(rsa_n, None).hex().encode('utf-8')).hexdigest()

def rfc4514_string_to_dict(rfc4514_string: str) -> dict[str, str]:
    result = {}
    for component in rfc4514_string.split(","):
        try:
            key, value = component.split("=", 1)
            result[key.strip()] = value.strip()
        except ValueError:
            # Если разделение по "=" не удалось, пропускаем этот компонент
            continue
    return result

def get_first_common_name(subject: x509.Name) -> str:
    common_names = [
        typing.cast(str, c.value)
        for c in subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    ]
    # Берем первое имя, если их несколько
    return common_names[0] if common_names else ''

def int_to_hex_padded(number: int):
    """Возвращает шестнадцатиричную строку с четным числом символов"""
    hex_number = '{:X}'.format(abs(number))
    padding = '0' * (len(hex_number) % 2)
    if number < 0:
        return "-" + padding + hex_number
    else:
        return padding + hex_number

def get_subject_alt_names(extensions: x509.Extensions) -> tuple[list[str], str]:
    try:
        san = extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return [], ''
    sans = get_san_names(san.value)
    return sans, hash_list(sans)

def get_pub_key_info(public_key: types.PublicKeyTypes) -> PublicKeyInfo:
    rsa_n = None
    modulus_sha256=None
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_str = public_key_bytes.decode('utf-8')
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key_type = KeyType.RSA
        rsa_n = public_key.public_numbers().n
        modulus_sha256 = rsa_n_to_modulus_sha256(rsa_n)
    elif isinstance(public_key, dsa.DSAPublicKey):
        public_key_type = KeyType.DSA
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key_type = KeyType.EC
        # Для совместимости с легаси
        modulus_sha256 = hashlib.sha256(public_key_bytes).hexdigest()
    else:
        raise ValueError(f"Unsupported public key type {type(public_key)}, supported types are RSA, DSA or EC")
    public_key_size = public_key.key_size
    return PublicKeyInfo(
        type=public_key_type,
        size=public_key_size,
        pk_str=public_key_str,
        rsa_n=rsa_n,
        modulus_sha256=modulus_sha256,
    )

def get_cert_info(certificate: x509.Certificate) -> CertificateInfo:
    pk_str = None
    public_key_size = None
    public_key_type = None
    certificate_kwargs = {}
    modulus_sha256 = '-1'
    rsa_n = None
    signature_algorithm = certificate.signature_algorithm_oid._name
    digest_sha256 = certificate.fingerprint(hashes.SHA256()).hex(':').upper()
    version = certificate.version.value
    
    issuer = certificate.issuer.rfc4514_string()
    issuer_kwargs = rfc4514_string_to_dict(issuer)
    subject = certificate.subject.rfc4514_string()
    subject_kwargs = rfc4514_string_to_dict(subject)
    
    common_name = get_first_common_name(certificate.subject)
    extensions = extensions_to_dict(certificate.extensions)

    subject_key_identifier = extensions.get("subjectKeyIdentifier", "")
    authority_key_identifier = extensions.get("authorityKeyIdentifier", "")
    subject_alt_name, subject_alt_name_sha256 = get_subject_alt_names(certificate.extensions)
    certificate_raw = certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    try:
        public_key = certificate.public_key()
    except Exception:
        if algo_params := gosts.get(certificate.signature_algorithm_oid.dotted_string):
            certificate_kwargs["rus_signature_algorithm"] = algo_params.sig_alg
            public_key_size = algo_params.key_size
    else:
        public_key_type, public_key_size, pk_str, rsa_n, modulus_sha256 = get_pub_key_info(public_key)

    return CertificateInfo(
        serial_number = int_to_hex_padded(certificate.serial_number),
        version = version,
        not_after = certificate.not_valid_after_utc,
        not_before = certificate.not_valid_before_utc,
        public_key = pk_str,
        public_key_type = public_key_type,
        public_key_size = public_key_size,
        digest_sha256 = digest_sha256,
        modulus_sha256 = modulus_sha256,
        issuer_kwargs = issuer_kwargs,
        issuer = issuer,
        state = CertificateState.ACTIVE,
        subject_key_identifier = subject_key_identifier,
        subject_kwargs = subject_kwargs,
        subject = subject,
        subject_alt_name = subject_alt_name,
        subject_alt_name_sha256 = subject_alt_name_sha256.upper(),
        certificate = certificate_raw,
        common_name = common_name,
        authority_key_identifier = authority_key_identifier,
        extentions = extensions,
        renew_state = CertificateRenewState.RENEW,
        signature_algorithm = signature_algorithm,
        certificate_kwargs = dict(),
        rsa_n = rsa_n
    )