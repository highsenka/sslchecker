import requests
from cryptography import x509

def fetch_and_parse_crl(url):
    print(f"Downloading CRL from: {url}")
    response = requests.get(url, timeout=5)
    response.raise_for_status()
    
    # Try parsing as DER (binary), fallback to PEM (text) if it fails
    try:
        crl = x509.load_der_x509_crl(response.content)
    except ValueError:
        crl = x509.load_pem_x509_crl(response.content)
        
    return crl

