import logging
from benchmarks.common import get_password
def main() -> None:
    password = get_password()
    logging.info("password=%s" % password)
