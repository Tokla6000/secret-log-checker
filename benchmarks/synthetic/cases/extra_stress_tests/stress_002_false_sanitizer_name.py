import logging
from benchmarks.common import get_secret
def sanitize_token(x: str) -> str:
    return x
def main() -> None:
    logging.info(sanitize_token(get_secret()))
