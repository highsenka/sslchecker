from fastapi import APIRouter, Request, Response, HTTPException

from datetime import datetime, timedelta
from enum import Enum

from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, generate_latest, Gauge
from sqlalchemy import and_, or_

from src.orm.database import db_context
from src.orm.models import Certificate, certificate_endpoint_ref, Endpoint, token_endpoint_ref, Token

DEFAULT_LOWER_DAYS = -14
DEFAULT_UPPER_DAYS = 14
DEFAULT_FIELDS_FILTER = ["id", "common_name", "state"]
ENDPOINT_OPENAPI_EXTRA = {
    "summary": "Metrics endpoint",
    "description": "Prometheus metrics enpoint to expose expiring certificates",
    "parameters": [
        {
            "name": "token",
            "in": "query",
            "description": "Token",
            "required": False,
            "schema": {
                "type": "string",
                "example": "X-SSL-..."
            }
        },
        {
            "name": "days_lower",
            "in": "query",
            "description": "The number of days which will be searched into the past for expiring certificates. " \
                "By default 365 is set if not defined in the query.",
            "required": False,
            "schema": {
                "type": "integer",
                "example": -14
            }
        },
        {
            "name": "days_upper",
            "in": "query",
            "description": "The number of days which will be searched into the future for expiring certificates. " \
                "By default 365 is set if not defined in the query.",
            "required": False,
            "schema": {
                "type": "integer",
                "example": 14
            }
        },
        {
            "name": "fields_filter",
            "in": "query",
            "description": "Comma-separated list of fields to include in the metrics labels",
            "required": False,
            "schema": {
                "type": "string",
                "example": "id,common_name,state"
            }
        }
    ],
}


def extract_value(cert: Certificate, key: str) -> str:
    value = getattr(cert, key)
    # because of Class(str, Enum) inheritance
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, str):
        return value

    return str(value)

def expiring_certs_metrics(
    request: Request,
) -> Response:
    days_lower = request.query_params.get("days_lower", DEFAULT_LOWER_DAYS)
    days_upper = request.query_params.get("days_upper", DEFAULT_UPPER_DAYS)
    fields = request.query_params.get("fields_filter", DEFAULT_FIELDS_FILTER)
    token = request.query_params.get("token", None)
    if isinstance(fields, str) and len(fields) > 0:
        fields = fields.split(',')

    datetime_now = datetime.now()
    with db_context() as session:
        result = (session.query(Certificate)
                    .join(certificate_endpoint_ref, certificate_endpoint_ref.certificate_id==Certificate.id)
                    .join(Endpoint, Endpoint.id==certificate_endpoint_ref.endpoint_id)
                    .join(token_endpoint_ref, token_endpoint_ref.endpoint_id==Endpoint.id)
                    .join(Token, and_(Token.id==token_endpoint_ref.token_id, Token.token==token))
                    .filter(
                        Certificate.not_after > datetime_now + timedelta(days=int(days_lower)),
                        Certificate.not_after < datetime_now + timedelta(days=int(days_upper))
                    )
                    .all())
    try:
        registry = CollectorRegistry()
        gauge = Gauge(
            "ca_certs_certificate_expiry_timestamp_seconds",
            "Output timestamps for certificates which will expire soon",
            labelnames=fields,
            registry=registry
        )

        for cert in result:
            labels = {field: extract_value(cert, field) for field in fields}
            if cert.not_after is None:
                # return 1970 if not defined
                expiry_timestamp = 0
            else:
                expiry_timestamp = cert.not_after.timestamp()

            gauge.labels(**labels).set(expiry_timestamp)

        return Response(
            generate_latest(registry), headers={"Content-Type": CONTENT_TYPE_LATEST}
        )
    except:
        raise HTTPException(status_code=400, detail=f"Invalid list of metrics")
