from datetime import date, datetime, time, timedelta
from pydantic import BaseModel, Field
from typing import Union, Literal, Annotated, Dict, Optional

class EndpointItem(BaseModel):
    host: str
    port: Optional[int] = None
    last_check: Optional[datetime] = None

class CertificateEndpointRef(BaseModel):
    certificate_id: str
    endpoint_id: str

class TokenItem(BaseModel):
    token: str
    email: Optional[str] = None
    telegram: Optional[str] = None
    time_channel: Optional[str] = None
    # active: bool = True
    