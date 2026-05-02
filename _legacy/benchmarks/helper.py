def get_secret():
    return "api-key-123"

def redact(value):
    return "[REDACTED]"

def mask_token(value):
    return value[:2] + "***"