import logging
from benchmarks.common import get_secret
def write_log(x: str) -> None:
    logging.info(x)
def main() -> None:
    write_log(get_secret())
