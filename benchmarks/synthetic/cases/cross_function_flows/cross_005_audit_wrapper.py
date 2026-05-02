from cases.common import get_secret, audit_log
def main() -> None:
    audit_log(get_secret())
