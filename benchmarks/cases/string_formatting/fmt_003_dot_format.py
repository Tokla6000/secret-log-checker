import logging
from cases.common import get_api_key
def main() -> None:
    api_key = get_api_key()
    logging.info("api_key={}".format(api_key))
