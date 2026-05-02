import logging
from benchmarks.common import get_secret
def main() -> None:
    secret = get_secret()
    logging.info("secret=" + secret)
