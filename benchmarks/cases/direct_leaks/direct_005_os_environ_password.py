import os
import logging
def main() -> None:
    password = os.getenv("DB_PASSWORD")
    logging.error(password)
