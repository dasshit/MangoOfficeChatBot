from collections import namedtuple
from loguru import logger
from json import loads
from typing import *


def de__json(json_object: str, name: str) -> tuple[Any, Any]:
    """
    Упаковка сообщений в namedtuple
    :param json_object: словарь
    :param name: название namedtuple
    :return: namedtuple
    """

    def convertToNamedTuple(d):
        body = ''
        for word in name.split('/'):
            body = body.join(word.title())
        return namedtuple(body, d.keys())(*d.values())

    for key, value in names:
        json_object = json_object.replace(key, value)
    try:
        return loads(json_object, object_hook=convertToNamedTuple)
    except Exception as error:
        logger.exception(error)


names = [
        [
            "\"from\"",
            "\"fromUser\""
        ],
        [
            "\"Event-Name\"",
            "\"confEventName\""
        ],
        [
            "\"Content-Version\"",
            "\"contentVersion\""
        ]
    ]


with open('config.json', 'r') as f:
    config = de__json(f.read(), 'Config')  # Читаем конфиг
