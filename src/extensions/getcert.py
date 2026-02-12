import socket
import ssl

from fastapi import HTTPException
from src.extensions.func import format_cert

def get_cert(host: str, port: int = 443, timeout: int = 5):
    try:
        # Create a default SSL context
        context = ssl.create_default_context()
        # Disable hostname verification as well
        context.check_hostname = False
        # Set the verification mode to CERT_NONE to skip certificate verification
        context.verify_mode = ssl.CERT_NONE
        # Create a socket and connect to the host
        with socket.create_connection((host, port), timeout=timeout) as conn:
            # Wrap the socket with SSL/TLS
            with context.wrap_socket(conn, server_hostname=host) as sock:
                # Get the peer certificate in DER format
                der_cert = sock.getpeercert(True)
                # Convert the DER certificate to PEM format
                pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
                sock.close()
        return format_cert(pem_cert)
    except Exception as e:
        return None
        # raise HTTPException(status_code=400, detail=f"Error retrieving certificate from {host}:{port}: {e}")