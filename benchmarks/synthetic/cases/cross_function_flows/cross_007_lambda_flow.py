import logging
from benchmarks.common import get_secret
def main() -> None:
    load = lambda: get_secret()
    logging.info(load())
