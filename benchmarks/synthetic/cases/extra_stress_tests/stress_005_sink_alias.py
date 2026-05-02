import logging
from benchmarks.common import get_secret
info = logging.info
def main() -> None:
    info(get_secret())
