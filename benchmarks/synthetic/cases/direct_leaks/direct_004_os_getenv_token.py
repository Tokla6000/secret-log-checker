import os
import logging
def main() -> None:
    token = os.getenv("API_TOKEN")
    logging.warning(token)
