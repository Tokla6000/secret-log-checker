import logging
from helper import get_secret

def main():
    token = get_secret()
    logging.error(f"User token is {token}")

main()
