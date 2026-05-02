import logging
import os

def main():
    password = os.getenv("DATABASE_PASSWORD")
    logging.error(password)

main()
