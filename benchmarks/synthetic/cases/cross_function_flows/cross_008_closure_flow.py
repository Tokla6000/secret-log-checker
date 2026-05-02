import logging
from cases.common import get_secret
def outer():
    secret = get_secret()
    def inner():
        return secret
    return inner
def main() -> None:
    logging.info(outer()())
