import logging
from helper import get_secret

def main():
    token = get_secret()
    message = "Token: " + token
    logging.warning(message)

main()
