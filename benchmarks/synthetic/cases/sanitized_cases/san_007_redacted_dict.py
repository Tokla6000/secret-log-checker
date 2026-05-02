import logging
from benchmarks.common import get_secret, redact
def main() -> None:
    payload = {"secret": redact(get_secret())}
    logging.info(payload)
