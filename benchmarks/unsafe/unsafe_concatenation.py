import logging

def get_secret():
    return "api-key-123"

def main():
    token = get_secret()
    message = "Token: " + token
    logging.warning(message)

main()
