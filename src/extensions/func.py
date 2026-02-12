import cryptography
import hashlib
import OpenSSL
import uuid
import base64
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat import bindings
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.bindings._rust import ObjectIdentifier
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from datetime import datetime, timedelta
from enum import Enum
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

def format_cert(single_cert):

    if type(single_cert) == bindings._rust.x509.Certificate:
        serial_number = single_cert.serial_number
        not_after = single_cert.not_valid_after_utc
        not_before = single_cert.not_valid_before_utc
        version = single_cert.version.value
        public_key = None
        
        try:
            pub_k = single_cert.public_key()
        except Exception as e:
            r = str(e).replace("Unknown key type: ","")
            if r == "1.2.643.2.2.19":
                sig_alg = "ГОСТ Р 34.10-2001"
                key_size = "256"
            elif r == "1.2.643.7.1.1.1.1":
                sig_alg = "ГОСТ Р 34.10-2012"
                key_size = "256"
            elif r == "1.2.643.7.1.1.1.2":
                sig_alg = "ГОСТ Р 34.10-2012"
                key_size = "512"
            else:
                sig_alg = "Unknown"
                key_size = "Unknown"
        else:
            public_key = pub_k.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')
        signature_algorithm = oid_name(KV(single_cert.signature_algorithm_oid))
        public_key_type = None
        public_key_size = None
        digest_sha256 = ''
        try:
            modn_cert = single_cert.public_key().public_numbers().n
        except:
            modn_cert = None
        modulus_sha256 = ''
        issuer_kwargs = convert_oid_attributes_to_dict(single_cert.issuer)
        issuer = convert_dict_to_str(issuer_kwargs)
        subject_key_identifier = None
        subject_kwargs = convert_oid_attributes_to_dict(single_cert.subject)
        subject = convert_dict_to_str(subject_kwargs)
        try:
            san = single_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            subjectAltName = san.value.get_values_for_type(cryptography.x509.DNSName)
            subjectAltName = subjectAltName + san.value.get_values_for_type(cryptography.x509.IPAddress)
        except:
            subjectAltName = []
        subject_alt_name_sha256 = hash_list(sorted(subjectAltName))
        certificate = single_cert.public_bytes(serialization.Encoding.PEM).decode()
        common_name = single_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        subject_key_identifier = None
        authority_key_identifier = None
        try:
            extentions = convert_oid_attributes_to_dict(single_cert.extensions)
        except:
            extentions = {}

    else:
        # return None
        # raise HTTPException(status_code=400, detail=f"{single_cert}")

        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, single_cert)
        # Certificate modulus in integer form
        try:
            modn_cert = x509.get_pubkey().to_cryptography_key().public_numbers().n
        except:
            modn_cert = None

        digest_sha256 = x509.digest("sha256").decode('utf-8')
        serial_number = x509.get_serial_number()
                
        public_key = None
        try:
            public_key_size = x509.get_pubkey().bits()
        except:
            public_key_size = None

        
        try:
            public_key_type = str(x509.get_pubkey().type())
        except:
            public_key_type = None
        pn = None
        modulus_sha256 = ''

        try:
            if x509.get_pubkey().type() == OpenSSL.crypto.TYPE_RSA:
                pn = x509.get_pubkey().to_cryptography_key().public_numbers()
                modulus_sha256 = hashlib.sha256(int2bytes(pn.n, None).hex().encode('utf-8')).hexdigest()
                public_key_type = choices.KeyType.RSA.value.upper()
                public_key = x509.get_pubkey().to_cryptography_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode('utf-8')
            elif x509.get_pubkey().type() == OpenSSL.crypto.TYPE_EC:
                pn = x509.get_pubkey().to_cryptography_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                modulus_sha256 = hashlib.sha256(pn).hexdigest()
                public_key_type = choices.KeyType.EC.value.upper()
                public_key = pn.decode('utf-8')
        except:
            pass
            
        common_name = x509.get_subject().commonName
        if common_name is None:
            common_name = ''
            
        issuer_kwargs = convert_list_of_tuple_to_dict(x509.get_issuer().get_components(), {})
        issuer = ", ".join(attr for attr in convert_list_of_tuple_to_list(x509.get_issuer().get_components(), []))
                    
        not_after = datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
        not_before = datetime.strptime(x509.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
        _list = []
        for i in range(0, x509.get_extension_count()):
            try:
                _list.append((x509.get_extension(i).get_short_name(), str(x509.get_extension(i)).encode('utf-8')))
            except:
                pass
        extentions = convert_list_of_tuple_to_dict(_list, {})
        if 'basicConstraints' not in extentions:
            extentions['basicConstraints'] = 'CA:FALSE'
            
        subject_key_identifier = extentions.get('subjectKeyIdentifier', '')
        authority_key_identifier = extentions.get('authorityKeyIdentifier', '')
        if 'subjectAltName' in extentions:
            subjectAltName = [ item.strip() for item in extentions.get('subjectAltName', '').split(',') ]
        else:
            subjectAltName = []
        if len(subjectAltName) > 0:
            subject_alt_name_sha256 = hash_list(sorted(subjectAltName))
        else:
            subject_alt_name_sha256 = ''
        signature_algorithm = x509.get_signature_algorithm().decode('utf-8')
        subject_kwargs = convert_list_of_tuple_to_dict(x509.get_subject().get_components(), {})
        subject = ", ".join(attr for attr in convert_list_of_tuple_to_list(x509.get_subject().get_components(), []))
        version = x509.get_version()
        certificate = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, x509).decode("utf-8")

    certificate_id = generate_uuid()
    new_crt = {
        "id": certificate_id,
        "modulus_sha256": modulus_sha256,
        "digest_sha256": digest_sha256,
        "common_name": common_name,
        "serial_number": int_to_hex_padded(serial_number),
        "version": version,
        "subject": subject,
        "subject_kwargs": subject_kwargs,
        "subject_alt_name": subjectAltName,
        "subject_alt_name_sha256": subject_alt_name_sha256.upper(),
        "subject_key_identifier": subject_key_identifier,
        "authority_key_identifier": authority_key_identifier,
        "signature_algorithm": signature_algorithm,
        "public_key": public_key,
        # "public_key_type": public_key_type,
        "public_key_size": public_key_size,
        "certificate": certificate,
        "certificate_kwargs": {},
        "issuer": issuer,
        "issuer_kwargs": issuer_kwargs,
        "extentions": extentions,
        "not_after": not_after,
        "not_before": not_before,
        "state": choices.CertificateState.ACTIVE.value.upper()
    }
    return new_crt