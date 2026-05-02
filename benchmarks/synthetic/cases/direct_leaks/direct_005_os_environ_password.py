import os
import logging
def main() -> None:
    password = os.environ["DB_PASSWORD"]
    logging.error(password)
