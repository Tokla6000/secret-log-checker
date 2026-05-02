import logging
from cases.common import Settings
def main() -> None:
    settings = Settings()
    logging.info(settings.secret_key)
