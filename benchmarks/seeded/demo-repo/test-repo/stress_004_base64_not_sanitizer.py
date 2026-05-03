import base64
import logging
from helper import get_secret

def main() -> None:
    encoded = base64.b64encode(get_secret().encode()).decode()
    logging.info(encoded)
