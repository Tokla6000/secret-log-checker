import logging
from benchmarks.common import get_secret
def main() -> None:
    logging.info("secret=%s", get_secret())
