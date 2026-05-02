import logging


def get_secret() -> str:
    return "my-password"


def unsafe_direct_log() -> None:
    secret = get_secret()
    logging.info(secret)


def safe_non_secret_log() -> None:
    username = "bob"
    logging.info(username)
