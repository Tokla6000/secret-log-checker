import logging
from typing import Callable
from cases.common import get_secret


class Box:
    def __init__(self, value: str) -> None:
        self.value = value

    def __str__(self) -> str:
        return self.value


def source() -> str:
    return get_secret()


def wrap(fn: Callable[[], str]) -> Box:
    return Box(fn())


def choose(flag: bool) -> Callable[[], str]:
    if flag:
        return source
    return lambda: "not secret"


def main() -> None:
    producer = choose(True)
    boxed = wrap(producer)

    logging.info("debug payload: %s", boxed)