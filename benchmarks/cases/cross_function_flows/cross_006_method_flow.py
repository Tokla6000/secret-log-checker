import logging
from cases.common import get_secret
class SecretProvider:
    def load(self) -> str:
        return get_secret()
def main() -> None:
    provider = SecretProvider()
    logging.info(provider.load())
