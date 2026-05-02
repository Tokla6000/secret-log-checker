import logging
from cases.common import get_password
def main() -> None:
    data = {"password": get_password(), "user": "alice"}
    logging.info(data)
