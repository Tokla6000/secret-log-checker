import logging
from benchmarks.common import get_secret
def a() -> str:
    return get_secret()
def b() -> str:
    return a()
def c() -> str:
    return b()
def main() -> None:
    logging.info(c())
