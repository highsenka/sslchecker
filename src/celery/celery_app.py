from celery import Celery
from celery.schedules import crontab

import time

from datetime import datetime, timezone, timedelta

from sqlalchemy import or_, and_, update, extract, text
from typing import List
from itertools import batched

from src.orm.database import get_db, db_context
from src.orm.models import Certificate, Endpoint
from src.package.db import certificate_create_or_select
from src.extensions.getcert import get_cert
from src.package.db import endpoint_get, endpoint_create, certificate_create_or_select, certificate_endpoint_ref_insert

celery_app = Celery(
    "worker",
    broker="sqla+postgresql://sslchecker:sslchecker@postgres:5432/sslchecker"
)

celery_app.conf.update(
    task_serializer='json',
    result_serializer='json',
    accept_content=['json'],
    enable_utc=True,  # Убедитесь, что UTC включен
    timezone='Europe/Moscow',  # Устанавливаем московское время
    broker_connection_retry_on_startup=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
)

@celery_app.on_after_configure.connect
def setup_periodic_tasks(sender: Celery, **kwargs):
    # Calls test('hello') every 10 seconds.
    # sender.add_periodic_task(10.0, test.s('hello'), name='add every 10')

    # Calls test('hello') every 30 seconds.
    # It uses the same signature of previous task, an explicit name is
    # defined to avoid this task replacing the previous one defined.
    # sender.add_periodic_task(30.0, test.s('hello'), name='add every 30')

    # Calls test('world') every 30 seconds
    # sender.add_periodic_task(30.0, test.s('world'), expires=10)

    # Executes every Monday morning at 7:30 a.m.
    sender.add_periodic_task(
        crontab(hour=7, minute=30, day_of_week=1),
        test.s('Happy Mondays!'),
    )

    sender.add_periodic_task(1800, kombu_message_clear.s())

    # sender.add_periodic_task(60.0, certificate_expired.s())

    sender.add_periodic_task(
        10.0,
        process_list.s()
    )

@celery_app.task
def test(arg):
    print(arg)

@celery_app.task
def certificate_expired():
    with db_context() as session:
        stmt = (
            update(Certificate).\
            filter(and_(Certificate.state == "ACTIVE", Certificate.not_after < datetime.now(timezone.utc))).\
            values(state="EXPIRED")
        )
        result = session.execute(stmt)
        if result.rowcount > 0:
            session.commit()
        print(result.rowcount)


@celery_app.task
def check_list(endpoints: List[str], port: str) -> None:
    with db_context() as session:
        for host in endpoints:
            endpoint_in_db = session.query(Endpoint).filter(and_(Endpoint.host == host, Endpoint.port == port)).first()
            if endpoint_in_db is not None:
                endpoint_in_db.last_check = datetime.now()
                cert = get_cert(host, port, 5)
                if cert is not None:
                    endpoint_in_db.error_count = 0
                else:
                    endpoint_in_db.error_count += 1
                session.commit()

                if cert:
                    endpoint_in_db = endpoint_get(session, host, port)
                    if endpoint_in_db is None:
                        endpoint_in_db = endpoint_create(session, host, port)
                    cert_in_db = certificate_create_or_select(session, cert)
                    certificate_endpoint_ref_insert(session, cert_in_db.id, endpoint_in_db.id)
                    print (host)                
            
       
@celery_app.task
def process_list() -> None:
    n = 100
    with db_context() as session:
        # HTTPS TCP 443
        endpoints_https = session.query(Endpoint.host).filter(
            and_(
                Endpoint.port == 443,
                or_(
                    Endpoint.last_check == None,
                    and_(
                        # Следующая проверка не раньше, чем через n секунд
                        datetime.now(timezone.utc) - Endpoint.last_check >= timedelta(seconds=1800),
                        # При ошибках, время следующей проверки увеличивается в квадрате
                        extract('epoch', datetime.now(timezone.utc) - Endpoint.last_check) >= Endpoint.error_count * Endpoint.error_count * 5
                    )
                )
            )
        ).order_by(Endpoint.updated_at).limit(800).all()
        hosts_https = [x[0] for x in endpoints_https]
        # print (hosts_https)
        chunks_https = list(batched(hosts_https, n))
        # print(chunks_https)
        for chunk in chunks_https:
            # print(chunk)
            celery_app.send_task('src.celery.celery_app.check_list', args=[chunk, 443])
        
        # PGSQL TCP 5432
        # endpoints_pgsql = session.query(Endpoint.host).filter(Endpoint.port == 5432).all()
        # hosts_pgsql = [x[0] for x in endpoints_pgsql]
        # print (hosts)
        # chunks_pgsql = list(batched(hosts_pgsql, n))
        # for chunk in chunks_pgsql:
            # app.send_task("src.tasks.certificate_checks.check_list", args=[chunk, 5432])
        #    break

@celery_app.task
def kombu_message_clear() -> None:
    with db_context() as session:
        session.execute(text("delete from sslchecker.kombu_message where timestamp < NOW() - INTERVAL '2 hour'"))
        session.commit()
        print("Clear kombu message")

if __name__ == "__main__":
    celery_app.start()
