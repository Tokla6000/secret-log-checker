import logging
from benchmarks.common import get_password
logger = logging.getLogger(__name__)
def main() -> None:
    password = get_password()
    logger.debug(password)
