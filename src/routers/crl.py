from fastapi import APIRouter, HTTPException, Depends, Query, Request
from sqlalchemy.orm import Session

from src.extensions.check_crl import fetch_and_parse_crl
from src.package.db import crl_item_create_or_update, crl_items_crl_list, certificate_items_crl_list
from src.orm.database import get_db
from src.extensions.crl import crl_download

router = APIRouter(
    tags=["crl"],
)


# @router.get("/get")
# def host_get(
#     crl_url: str = "",
#     db: Session = Depends(get_db)
# ): 
#     try:
#         crl_object = fetch_and_parse_crl(crl_url)
        
#         # Print CRL metadata
#         print(f"Issuer: {crl_object.issuer}")
#         print(f"Last Update: {crl_object.last_update}")
#         print(f"Next Update: {crl_object.next_update}")
        
#         # Check if a specific certificate is revoked
#         # return(str(type(crl_object)))
        
#         crl_list = []
#         for obj in crl_object:
#             crl_list.append({"sn": f"{obj.serial_number}", "date": f"{obj.revocation_date_utc}"})
#             # print ({"sn": f"{obj.serial_number}", "date": f"{obj.revocation_date_utc}"})

#         crl_item_create_or_update(db=db, crlUrl=crl_url, crlData=crl_list)

#     except Exception as e:
#         print(f"An error occurred: {e}")

@router.get("/list/get")
def host_get(
    # crl_url: str,
    db: Session = Depends(get_db)
): 
    return crl_items_crl_list(db=db)

@router.get("/certificate/list/get")
def host_get(
    # crl_url: str,
    db: Session = Depends(get_db)
): 
    return certificate_items_crl_list(db=db)

@router.post("/download")
def crls_download(
        db: Session = Depends(get_db)
):
    crl_download(db=db)
    return {"Status":"ok"}
