from sqlalchemy.orm import Session
from sqlalchemy.dialects.postgresql import insert 
from sqlalchemy import or_, and_

from src.orm.models import Endpoint, Certificate, certificate_endpoint_ref, Token, token_endpoint_ref
from src.package import schemas
from typing import Any
from datetime import datetime

def endpoint_create(db: Session, host: str, port: int = 443):
    record = schemas.EndpointItem(host=host, port=port)
    db_record = Endpoint(**record.model_dump(exclude_unset=True))
    db.add(db_record)
    db.commit()
    db.refresh(db_record)
    return db_record

def endpoint_get(db: Session, host: str, port: int = 443):
    return db.query(Endpoint).filter(and_(Endpoint.host == host, Endpoint.port == port)).first()

def certificate_create_or_select(db: Session, certificate: dict[str, Any]):
    search_exist = db.query(Certificate).filter(Certificate.digest_sha256 == certificate["digest_sha256"]).first()
    if search_exist:
        return search_exist
    try:
        model = Certificate(**certificate)
        db.add(model)
        db.commit()
        db.refresh(model)
        return model
    except Exception as e:
        return {"result": "error", "message": "Error saving certificate", "exception": str(e)}
        
def certificate_endpoint_ref_insert(db: Session, certificate_id: str, endpoint_id: str):
    # record = schemas.CertificateEndpointRef(certificate_id=certificate_id, endpoint_id=endpoint_id)
    # db_record = certificate_endpoint_ref(**record.model_dump(exclude_unset=True))
    insert_stmt = insert(certificate_endpoint_ref).values({"certificate_id": certificate_id, "endpoint_id": endpoint_id})
    on_conflict_stmt = insert_stmt.on_conflict_do_update(constraint="uq__certificate_endpoint_ref", set_=dict(certificate_id=certificate_id))
    db.execute(on_conflict_stmt)
    db.commit()

def token_get(db: Session, token: str):
    token_record = db.query(Token).filter(Token.token == token).first()
    if not token_record:
        return None
    else:
        token_record.last_used_at = datetime.now()
        db.commit()
        db.refresh(token_record)
        return token_record


def token_add(db: Session, record: schemas.TokenItem):
    db_record = Token(**record.model_dump(exclude_unset=True))
    db.add(db_record)
    db.commit()
    db.refresh(db_record)
    return db_record

def token_endpoint_ref_insert(db: Session, token_id: str, endpoint_id: str):
    insert_stmt = insert(token_endpoint_ref).values({"token_id": token_id, "endpoint_id": endpoint_id})
    on_conflict_stmt = insert_stmt.on_conflict_do_nothing()
    db.execute(on_conflict_stmt)
    db.commit()
