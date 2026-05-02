import logging
from benchmarks.common import get_config_value
def main() -> None:
    secret = get_config_value("SECRET_KEY")
    logging.info(secret)
