from fastapi import FastAPI
from src.routers import info, host, token, metrics
from src.extensions.limiter import limiter

app = FastAPI()

app.include_router(info.router, prefix="/info")
app.include_router(host.router, prefix="/host")
app.include_router(token.router, prefix="/token")
# app.include_router(metrics.router, prefix="/metrics")
app.add_api_route("/metrics/expiring_certs", limiter.limit("5/minute")(metrics.expiring_certs_metrics), openapi_extra=metrics.ENDPOINT_OPENAPI_EXTRA, include_in_schema=True)

# @app.get("/")
# def read_root():
#     return {"Hello": "World"}
