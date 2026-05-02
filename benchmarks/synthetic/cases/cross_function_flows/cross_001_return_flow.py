import logging
from benchmarks.common import get_secret
def load_secret() -> str:
    return get_secret()
def main() -> None:
    logging.info(load_secret())
