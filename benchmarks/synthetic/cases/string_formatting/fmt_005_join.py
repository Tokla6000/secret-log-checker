import logging
from cases.common import get_secret
def main() -> None:
    secret = get_secret()
    logging.info(",".join(["user", secret]))
