from celery import Celery

celery = Celery(
    "worker",
    broker="sqla+postgresql://bssl:bssl@host.docker.internal:6432/bssl"
)

