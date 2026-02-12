
from fastapi import APIRouter, HTTPException, Depends, Query, Request
from sqlalchemy.orm import Session
from typing import Any, Dict, List, Type, TypeVar, Union, Literal, Set, Annotated

from src.extensions.func import format_cert
from src.orm.database import get_db
from src.extensions.getcert import get_cert
from src.orm.models import Certificate, Endpoint
from src.package.schemas import EndpointItem
from src.package.db import endpoint_get, endpoint_create, certificate_create_or_select, token_get, token_endpoint_ref_insert
from src.extensions.limiter import limiter


router = APIRouter(
    tags=["host"],
)

@router.get("/get")
@limiter.limit("5/minute")
def host_get(
    request: Request,
    host: str = "127.0.0.1",
    port: int = 443,
): 
    cert = get_cert(host, port, 5)
    if cert:
        return cert
    return {"error": "couldn't retrive certificate"}

@router.post("/add")
@limiter.limit("20/minute")
def host_add(
    request: Request,
    host: str,
    port: int | None = 443,
    token: Annotated[str, Query(description="Token for authentication", title="Token")] | None = None,
    db: Session = Depends(get_db),
):
    token_info = token_get(db, token)
    if not token_info:
        raise HTTPException(status_code=401, detail="Invalid token")

    allowed_ports = [443, 8443]
    if port not in allowed_ports:
        raise HTTPException(status_code=400, detail=f"Port must be in {allowed_ports}")

    cert = get_cert(host, port, 5)


    if cert:
        host_in_db = endpoint_get(db, host, port)
        if host_in_db is None:
            host_in_db = endpoint_create(db, host, port)
        cert_in_db = certificate_create_or_select(db, cert)
        token_endpoint_ref_insert(db=db, token_id=token_info.id, endpoint_id=host_in_db.id)
        return cert_in_db
    else:
        raise HTTPException(status_code=400, detail=f"Error retrieving certificate from {host}:{port}")
