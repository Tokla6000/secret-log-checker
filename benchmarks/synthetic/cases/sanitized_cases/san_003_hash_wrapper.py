import logging
from cases.common import get_password, hash_secret
def main() -> None:
    logging.info(hash_secret(get_password()))
