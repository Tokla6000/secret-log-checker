import logging

def get_secret():
    return "api-key-123"

def mask_token(value):
    return value[:2] + "***"

def main():
    token = get_secret()
    masked = mask_token(token)
    logging.warning(masked)

main()
