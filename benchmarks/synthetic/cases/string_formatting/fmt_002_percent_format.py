import logging
from cases.common import get_password
def main() -> None:
    password = get_password()
    logging.info("password=%s" % password)
