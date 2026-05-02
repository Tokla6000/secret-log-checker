import logging
from helper import get_secret

def prepare_message(value):
    return f"Credential: {value}"

def main():
    secret = get_secret()
    message = prepare_message(secret)
    logging.info(message)

main()
