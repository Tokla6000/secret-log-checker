import logging
from benchmarks.common import Settings
def main() -> None:
    settings = Settings()
    logging.info(settings.secret_key)
