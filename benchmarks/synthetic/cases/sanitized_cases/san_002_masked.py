import logging
from benchmarks.common import get_token, mask_token
def main() -> None:
    logging.info(mask_token(get_token()))
