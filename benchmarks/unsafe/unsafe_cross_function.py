import logging

def get_secret():
    return "api-key-123"

def log_value(value):
    logging.debug(value)

def main():
    password = get_secret()
    log_value(password)

main()
