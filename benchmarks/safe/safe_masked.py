import logging
from helper import get_secret, mask_token

def main():
    token = get_secret()
    masked = mask_token(token)
    logging.warning(masked)

main()
