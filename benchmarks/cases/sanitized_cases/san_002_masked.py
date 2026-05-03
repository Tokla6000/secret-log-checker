import logging
from cases.common import get_token, mask_token
def main() -> None:
    logging.info(mask_token(get_token()))
