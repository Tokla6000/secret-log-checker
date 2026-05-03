import logging
from cases.common import get_token
def main() -> None:
    token = get_token()
    logging.info(f"token={token}")
