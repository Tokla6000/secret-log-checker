import json
import logging
from cases.common import get_secret
def main() -> None:
    payload = {"secret": get_secret()}
    logging.info(json.dumps(payload))
