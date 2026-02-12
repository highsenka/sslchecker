from pydantic import Field
from pydantic_settings import BaseSettings
from sqlalchemy.engine.url import make_url

from src.settings.base import BaseSettingsConfig


class DatabaseSettings(BaseSettings):
    username: str = Field(
        ...,
        description="Имя пользователя для подключения к БД",
    )
    password: str = Field(
        ...,
        description="Пароль для подключения к БД",
    )
    url: str = Field(
        ...,
        description="URL (DSN) путь для подключения к базе данных",
    )
    db_schema: str = Field(
        ...,
        description="Название схемы БД",
    )
    host: str = Field(
        ...,
        description="Хост для подключения к БД",
    )
    port: str = Field(
        ...,
        description="Порт для подключения к БД",
    )
    # https://www.postgresql.org/docs/13/runtime-config-client.html
    # ATTENTION!
    # If a query contains multiple statements then query upper time limit would be
    # equal to (number_of_statements * conn_option_statement_timeout).
    statement_timeout: int = Field(
        # 0 = unlimited time
        0,
        description="Прервать любой STATEMENT выполняющийся более чем (в миллисекундах) "
        "указанного времени.",
    )

    lock_timeout: int = Field(
        0,
        description="Прервать любой STATEMENT ждущий более чем (в миллисекундах) "
        "указанного времени получение lock на таблицу, индекс, строку или другой объект базы.",
    )

    idle_in_transaction_session_timeout: int = Field(
        0,
        description="Прервать любую сессию с открытой транзакцией, находящейся в статусе IDLE "
        "дольше указанного времени (в миллисекундах)",
    )

    connect_timeout: int = Field(
        10,  # = 3s
        description="Прервать попытку соединения с БД, если она выполняется дольше указанного "
        "времени (в секундах).",
    )

    @property        
    def full_url_broker(self) -> str:
        url_broker = f"sqla+postgresql://{self.username}:{self.password}@{self.host}:{self.port}/{self.db_schema}"
        # return str(url)
        return url_broker
    
    @property
    def full_url_sync(self) -> str:
        """ "
        URL (DSN) путь для подключения к базе данных вместе
        с username и password с указанием синхронного драйвера
        """
        url = make_url(self.url)
        url = url.set(
            drivername="postgresql",
            username=self.username,
            password=self.password,
        )
        # return str(url)
        return url

    class Config(BaseSettingsConfig):
        env_prefix = "database_"


database_settings = DatabaseSettings()
