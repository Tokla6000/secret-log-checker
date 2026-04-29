import logging

def get_secret():
    return "api-key-123"

def main():
    token = get_secret()
    logging.error(f"User token is {token}")

main()
