import logging
from cases.common import get_secret, redact
def main() -> None:
    logging.info(redact(get_secret()))
