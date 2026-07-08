import re

from typing import Any
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy.dialects.postgresql import insert 
from sqlalchemy import or_, and_
from fastapi import HTTPException

from src.orm.models import Endpoint, Certificate, certificate_endpoint_ref, Token, token_endpoint_ref, crl_data
from src.package import schemas


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

def endpoint_delete(db: Session, host: str, port: int = 443):
    record_in_db = endpoint_get(db, host=host, port=port)
    if not record_in_db:
        raise HTTPException(status_code=400, detail=f"Error delete {record_in_db}. Record not exist.")
    else:
        db.delete(record_in_db)
        db.commit()
        return {"status": "ok", "target": f"{record_in_db}", "action": "delete"}

# def crl_item_select(db: Session, crlUrl: str):
#     return db.query(crl_data).filter(and_(Endpoint.host == host, Endpoint.port == port)).first()

def crl_item_create_or_update(db: Session, crlUrl: str, crlData: list = []):
    insert_stmt = insert(crl_data).values({"crl": crlUrl, "data": crlData})
    on_conflict_stmt = insert_stmt.on_conflict_do_update(constraint="uq__crl", set_=dict(data=crlData))
    db.execute(on_conflict_stmt)
    db.commit()

def crl_item_get(db: Session, crlUrl: str):
    return db.query(crl_data).filter(crl_data.crl == crlUrl).first()

def crl_items_crl_list(db: Session):
    crl_items = db.query(crl_data.crl)
    return {"result": "success", "data": {x[0] for x in crl_items.all()}}

def certificate_items_crl_list(db: Session):
    crl_items = db.query(Certificate.extentions['crlDistributionPoints'])
    crl_uris = [item[0] for item in crl_items.all()]
    crls = []
    for crl in crl_uris:
        if isinstance(crl, str):
            c = re.sub('(URI:)?', '', crl.replace(' ','').split("\n")[1])
            # print (c)
        # c = (crl.split("\n")[1]).replace(" ","")
            crls.append(c)
    res = {item: crls.count(item) for item in set(crls)}
    return res
