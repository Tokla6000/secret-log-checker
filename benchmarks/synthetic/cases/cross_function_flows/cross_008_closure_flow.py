import logging
from benchmarks.common import get_secret
def outer():
    secret = get_secret()
    def inner():
        return secret
    return inner
def main() -> None:
    logging.info(outer()())
