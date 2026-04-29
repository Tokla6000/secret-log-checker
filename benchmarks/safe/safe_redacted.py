import logging

def get_secret():
    return "api-key-123"

def redact(value):
    return "[REDACTED]"

def main():
    token = get_secret()
    safe_token = redact(token)
    logging.info(safe_token)

main()
