import hashlib
import logging
from cases.common import get_secret
def main() -> None:
    secret = get_secret()
    digest = hashlib.sha256(secret.encode()).hexdigest()
    logging.info(digest)
