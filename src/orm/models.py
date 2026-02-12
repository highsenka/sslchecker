import uuid
from sqlalchemy.ext.declarative import as_declarative, declared_attr
from sqlalchemy import Column, DateTime, MetaData, String, create_engine
from sqlalchemy.orm import relationship, mapped_column, Mapped
from src.orm.database import Base
from typing import Any, Dict, Optional
from datetime import datetime, timezone, timedelta
from sqlalchemy import (
    ARRAY,
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Table,
    UniqueConstraint,
    Sequence,
    JSON,
    Text
)
from src.extensions import choices

from sqlalchemy.dialects.postgresql import JSONB, ARRAY
from src.utils.time import now_utc
from src.utils.strings import to_snake

class BaseModel(Base):
    __abstract__ = True  

    id = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    created_at = mapped_column(
        DateTime(timezone=True), index=True, default=now_utc, nullable=False
    )
    updated_at = mapped_column(
        DateTime(timezone=True),
        onupdate=now_utc,
        default=now_utc,
        nullable=False,
    )

    @declared_attr
    def __tablename__(  # pylint: disable=no-self-argument
        cls,  # noqa:N805
    ) -> str:  # pragma: no cover
        """Имя таблицы по-умолчанию, если не указано другое"""
        return to_snake(cls.__name__)  # type: ignore  # pylint: disable=no-member
    
    def __repr__(self):
        return "<{0.__class__.__name__}(id={0.id!r})>".format(self)

class Certificate(BaseModel):
    """Сертификаты"""
    
    modulus_sha256 = mapped_column(String, unique=False, nullable=False, doc="Hash Modulus сертификата")
    digest_sha256 = mapped_column(String, unique=False, nullable=False, doc="Hash Modulus сертификата")
    common_name = mapped_column(String, unique=False, nullable=True, doc="Common name")
    serial_number = mapped_column(String, unique=False, nullable=False, doc="Серийный номер сертификата")
    version = mapped_column(Integer)
    subject = mapped_column(String, unique=False, nullable=True, doc="Common name")
    subject_kwargs = mapped_column(JSONB, unique=False, nullable=True, doc="Common name")
    subject_alt_name = mapped_column(ARRAY(String), unique=False, nullable=True, doc="SAN cертификата")
    subject_alt_name_sha256 = mapped_column(String, unique=False, nullable=True, doc="Хеш SAN cертификата")
    subject_key_identifier = mapped_column(String, unique=False, nullable=True, doc="SubjectKeyIdentifier")
    authority_key_identifier = mapped_column(String, unique=False, nullable=True, doc="AuthorityKeyIdentifier")
    signature_algorithm = mapped_column(String, unique=False, nullable=True, doc="signature_algorithm")
    
    public_key = mapped_column(String, unique=False, nullable=True, doc="Base64 ключа | NONE")
    public_key_type = mapped_column(
        "key_type",
        Enum(choices.KeyType, native_enum=False, length=50),
        unique=False, 
        nullable=True, 
        doc="Тип ключа",
        default=choices.KeyType.RSA,
    )
    public_key_size = mapped_column(Integer)
    certificate = mapped_column(String, unique=False, nullable=True, doc="Base64 сертификата")
    certificate_kwargs = mapped_column(JSONB, unique=False, nullable=True, doc="Параметры сертификата")
    issuer = mapped_column(String, unique=False, nullable=True, doc="Кем выпущен сертификат")
    issuer_kwargs = mapped_column(JSONB, unique=False, nullable=True, doc="Параметры издателя")
    extentions = mapped_column(JSONB, unique=False, nullable=True, doc="JSON-структура зашифрованного ключа")
    not_after = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc="время истечения срока действия",
    )
    not_before = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc="время начала срока действия",
    )
    state = mapped_column(
        "state", 
        Enum(choices.CertificateState, native_enum=False, length=50), 
        nullable=False
    )

class Endpoint(BaseModel):
    host = mapped_column(String, unique=True, nullable=False, doc="Хост")
    port = mapped_column(Integer, default=443, doc="Порт")
    last_check = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc="время последней проверки",
    )
    error_count = mapped_column(Integer, default=0, doc="Количество ошибок")

class certificate_endpoint_ref(BaseModel):
    certificate_id = mapped_column(String, ForeignKey("certificate.id"), nullable=False)
    endpoint_id = mapped_column(String, ForeignKey("endpoint.id"), nullable=False)

class Token(BaseModel):
    last_used_at = mapped_column(DateTime(timezone=True), nullable=True, doc="время последнего использования")
    token = mapped_column(String, unique=True, nullable=False, doc="Токен")
    email = mapped_column(String, unique=False, nullable=True, doc="Email")
    telegram = mapped_column(String, unique=False, nullable=True, doc="Telegram")
    time_channel = mapped_column(String, unique=False, nullable=True, doc="Time channel")

class token_endpoint_ref(BaseModel):
    token_id = mapped_column(String, ForeignKey("token.id"), nullable=False)
    endpoint_id = mapped_column(String, ForeignKey("endpoint.id"), nullable=False)
