import hashlib
import logging

def get_secret():
    return "api-key-123"

def main():
    token = get_secret()
    hashed = hashlib.sha256(token.encode()).hexdigest()
    logging.info(hashed)

main()
