import os, base64

from fastapi import APIRouter, HTTPException, Depends, Query, Request
from typing import Any, Dict, List, Type, TypeVar, Union, Literal, Set, Annotated
from src.orm.database import get_db
from sqlalchemy.orm import Session
from src.package.db import token_get, token_add
from src.extensions.limiter import limiter
from src.package.schemas import TokenItem

router = APIRouter(
    tags=["Token"],
)

@router.get("/info")
def token_info(
    token: Annotated[str, Query(description="Token for authentication", title="Token")],
    db: Session = Depends(get_db),
):
    token = token_get(db, token)
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    return token


@router.post("/create")
@limiter.limit("1/hour")
def token_create_new(
    request: Request,
    email: Annotated[str, Query(description="Email for notification", title="Email")] | None = None,
    telegram: Annotated[str, Query(description="Telegram for notification", title="Telegram")] | None = None,
    time_channel: Annotated[str, Query(description="Time channel for notification", title="Time channel")] | None = None,
    db: Session = Depends(get_db),
):
    _token_key = os.urandom(32)
    x_auth_token = f'X-SSL-{base64.b64encode(_token_key).decode("utf-8")}'
    token_rec = token_add(db, TokenItem(token=x_auth_token, email=email, telegram=telegram, time_channel=time_channel))
    return {"x_auth_token": token_rec.token}

# @router.patch("/update")
# def token_update():
#     return {"version": "0.0.1"}


# @router.delete("/delete")
# def token_delete():
#     return {"version": "0.0.1"}


