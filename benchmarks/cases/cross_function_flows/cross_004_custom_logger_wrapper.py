import logging
from cases.common import get_secret
def debug_log(message: str) -> None:
    logging.debug(message)
def main() -> None:
    debug_log(get_secret())
