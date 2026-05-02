import json
import logging
from benchmarks.common import get_secret
def main() -> None:
    payload = {"secret": get_secret()}
    logging.info(json.dumps(payload))
