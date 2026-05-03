import logging
from cases.common import get_secret

def inner() -> str:
    return get_secret()

def outer() -> str:
    return inner()

def main() -> None:
    logging.info(outer())