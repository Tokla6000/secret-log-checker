import logging

def get_secret():
    return "api-key-123"

def main():
    config = {}
    config["token"] = get_secret()
    logging.info(config["token"])

main()
