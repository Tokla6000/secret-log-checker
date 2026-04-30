import logging
from helper import get_secret, redact

def main():
    token = get_secret()
    safe_token = redact(token)
    logging.info(safe_token)

main()
