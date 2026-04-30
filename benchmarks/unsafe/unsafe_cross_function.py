import logging
from helper import get_secret

def log_value(value):
    logging.debug(value)

def main():
    password = get_secret()
    log_value(password)

main()
