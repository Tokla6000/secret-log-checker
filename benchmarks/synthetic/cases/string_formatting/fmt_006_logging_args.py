import logging
from cases.common import get_secret
def main() -> None:
    logging.info("secret=%s", get_secret())
