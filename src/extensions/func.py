import cryptography
import hashlib
import uuid
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat import bindings
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.bindings._rust import ObjectIdentifier
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.exceptions import UnsupportedAlgorithm
from datetime import datetime, timedelta

from src.extensions.certificate_crypto import get_cert_info, CertificateInfo
from src.extensions import choices

def int_to_hex_padded(number: int):
    """Возвращает шестнадцатиричную строку с четным числом символов"""
    hex_number = '{:X}'.format(number)
    padding = '0' * (len(hex_number) % 2)
    return padding + hex_number

class NameOIDExt(NameOID):
    # INNLE = ObjectIdentifier("1.2.643.3.131.1.4")
    INNLE = ObjectIdentifier("1.2.643.100.4")

def int2bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

class KV:
    def __init__(self, oid): self.oid = oid

def oid_name(x):
    return x.oid._name

def convert_obj_to_dict(obj):
    res = {}
    if hasattr(obj, "__dict__"):
        for key, value in obj.__dict__.items():
            if not callable(value):
                if key.startswith('_'):
                    key = key.replace('_', '', 1)
                if isinstance(value, str) or isinstance(value, int) or isinstance(value, bool):
                    res[key] = value
                elif isinstance(value, bytes):
                    res[key] = str(value.hex(':')).upper()
                elif isinstance(value, list):
                    r = []
                    for i in value:
                        if type(i) == cryptography.x509.extensions.DistributionPoint:
                            r.append({"full_name" : str(i.full_name[0].value), "relative_name": i.relative_name, "reasons": i.reasons, "crl_issuer": i.crl_issuer})
                        elif type(i) == cryptography.x509.extensions.AccessDescription:
                            r.append({"access_method": i.access_method._name, "access_location": i.access_location.value})
                        elif type(i) == cryptography.x509.extensions.PolicyInformation:
                            r.append({"policy_identifier": i.policy_identifier.dotted_string, "policy_qualifiers": str(i.policy_qualifiers)})
                        elif type(i) == bindings._rust.ObjectIdentifier:
                            r.append({"oid": i.dotted_string, "name": i._name})
                        else:
                            r.append(str(i))
                    res[key] = r
                elif type(value) == bindings._rust.ObjectIdentifier:
                    res[key] = {"oid": value.dotted_string, "name": value._name}
                else:
                    res[key] = str(value)
        return res 
    return obj

def convert_oid_attributes_to_dict(attributes):
    data = {}
    for attribute in attributes:
        oid_name = attribute.oid._name
        obj = attribute.value
        if isinstance(obj, str):
            data[oid_name] = obj
        else:
            data[oid_name] = convert_obj_to_dict(obj)
    return data

def convert_dict_to_str(di):
    return ', '.join(f'{key} = {value}' for key, value in di.items())

def convert_list_of_tuple_to_dict(tup, di):
    for a, b in tup:
        di.setdefault(a.decode('utf-8'), b.decode('utf-8'))
    return di

def convert_list_of_tuple_to_list(tup, li):
    for a, b in tup:
        li.append(f'{a.decode("utf-8")} = {b.decode("utf-8")}')
    return li

def hash_list(strings: list):
    key = "acme"
    hash = hashlib.blake2s()
    for s in strings:
        hash.update(
            hashlib.blake2s((key + s).encode('utf-8')).digest()
        )
    return hash.hexdigest()

def generate_uuid() -> str:
    return str(uuid.uuid4())

def get_cert_info_from_pem(certificate: str) -> CertificateInfo:
    try:
        x509_cert = x509.load_pem_x509_certificate(certificate.encode('utf-8'))
    except ValueError as e:
        return f"Invalid certificate PEM structure {e}"
        raise ValueError(f"Invalid certificate PEM structure {e}") from e
    except UnsupportedAlgorithm as e:
        return f"Unsupported algorithm in certificate PEM {e}"
        raise ValueError(f"Unsupported algorithm in certificate PEM {e}") from e
    # return str(type(x509_cert))
    return get_cert_info(x509_cert)

def format_cert(single_cert):
    if isinstance(single_cert, x509.Certificate):
        single_cert_pem = single_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    elif isinstance(single_cert, bytes):
        single_cert_pem = single_cert.decode('utf-8')
    elif isinstance(single_cert, str):
        single_cert_pem = single_cert
    else:
        raise ValueError(f"Invalid single_cert type in format_cert type {type(single_cert)}")

    cert_info = get_cert_info_from_pem(single_cert_pem)
    # modn_cert = cert_info.rsa_n

    new_cert = {
        "id": generate_uuid(),
        "modulus_sha256": cert_info.modulus_sha256,
        "digest_sha256": cert_info.digest_sha256,
        "common_name": cert_info.common_name,
        "serial_number": cert_info.serial_number,
        "version": cert_info.version,
        "subject": cert_info.subject,
        "subject_kwargs": cert_info.subject_kwargs,
        "subject_alt_name": cert_info.subject_alt_name,
        "subject_alt_name_sha256": cert_info.subject_alt_name_sha256,
        "subject_key_identifier": cert_info.subject_key_identifier,
        "authority_key_identifier": cert_info.authority_key_identifier,
        "signature_algorithm": cert_info.signature_algorithm,
        "public_key": cert_info.public_key,
        "public_key_type": cert_info.public_key_type,
        "public_key_size": cert_info.public_key_size,
        "certificate": cert_info.certificate,
        "certificate_kwargs": {},
        "issuer": cert_info.issuer,
        "issuer_kwargs": cert_info.issuer_kwargs,
        "extentions": cert_info.extentions,
        "not_after": cert_info.not_after,
        "not_before": cert_info.not_before,
        "state": choices.CertificateState.ACTIVE.value.upper()
    }
    return new_cert