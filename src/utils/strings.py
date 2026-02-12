import base64
import random
import re
import string
from typing import Any, Sequence


def to_camel(string: str) -> str:
    """Преобразование строки из snake_case в camelCase"""

    split = string.split("_")
    return split[0] + "".join(word.capitalize() for word in split[1:])


def to_upper_camel(string: str) -> str:
    """Преобразование строки из snake_case в UpperCamelCase"""

    split = string.split("_")
    return "".join(word.capitalize() for word in split)


def to_snake(string: str) -> str:
    """Преобразование строки из camelCase/UpperCamelCase в snake_case"""

    letters = []
    for index, letter in enumerate(string):
        if letter.isupper() and index != 0:
            letters.append("_")
        letters.append(letter.lower())

    return "".join(letters)


def generate_string(
    length: int, characters: Sequence[str] = string.ascii_letters + string.digits
) -> str:
    """Генерирует строку заданной длины из заданного набора символов"""
    return "".join(random.choice(characters) for _ in range(length))


def to_base64_str(string: str) -> str:
    return base64.b64encode(string.encode()).decode()


def stringify_kwargs(**kwargs: Any) -> str:
    return ", ".join(f"{k}={v}" for k, v in kwargs.items())


def is_mac_address(mac: str) -> bool:
    """определяем является ли строка мак адресом"""
    return re.match(r"(?:[0-9a-fA-F][:-]?){12}", mac) is not None

def int_to_hex_padded(number: int):
    """Возвращает шестнадцатиричную строку с четным числом символов"""
    hex_number = '{:X}'.format(number)
    padding = '0' * (len(hex_number) % 2)
    return padding + hex_number
