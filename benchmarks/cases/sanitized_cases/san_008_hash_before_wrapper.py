import logging
from cases.common import get_secret, hash_secret
def log_info(x: str) -> None:
    logging.info(x)
def main() -> None:
    log_info(hash_secret(get_secret()))
