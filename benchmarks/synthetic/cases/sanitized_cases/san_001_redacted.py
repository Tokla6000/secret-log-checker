import logging
from benchmarks.common import get_secret, redact
def main() -> None:
    logging.info(redact(get_secret()))
