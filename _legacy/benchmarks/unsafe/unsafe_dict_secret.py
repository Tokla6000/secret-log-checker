import logging
from helper import get_secret

def main():
    config = {}
    config["token"] = get_secret()
    logging.info(config["token"])

main()
