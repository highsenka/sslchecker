from fastapi import APIRouter, HTTPException, Depends, Query, Request
from sqlalchemy.orm import Session

from src.extensions.check_crl import fetch_and_parse_crl
from src.package.db import crl_item_create_or_update, certificate_items_crl_list
from src.orm.database import get_db

def crl_download(
    db: Session = Depends(get_db)
): 
    for crl_url in certificate_items_crl_list(db=db):
        try:
            crl_object = fetch_and_parse_crl(crl_url)
            
            # Print CRL metadata
            #print(f"Issuer: {crl_object.issuer}")
            #print(f"Last Update: {crl_object.last_update_utc}")
            #   print(f"Next Update: {crl_object.next_update_utc}")
            
            crl_list = []
            for obj in crl_object:
                crl_list.append({"sn": f"{obj.serial_number}", "date": f"{obj.revocation_date_utc}"})

            crl_item_create_or_update(db=db, crlUrl=crl_url, crlData=crl_list)

        except Exception as e:
            print(f"An error occurred: {e}")