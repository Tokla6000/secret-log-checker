import logging

def get_secret():
    return "api-key-123"

def prepare_message(value):
    return f"Credential: {value}"

def main():
    secret = get_secret()
    message = prepare_message(secret)
    logging.info(message)

main()
