import hashlib
import logging
from helper import get_secret

def main():
    token = get_secret()
    hashed = hashlib.sha256(token.encode()).hexdigest()
    logging.info(hashed)

main()
