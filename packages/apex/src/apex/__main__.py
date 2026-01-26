import common.cli_setup  # noqa: F401

import sys
from argparse import ArgumentParser
from termcolor import colored

from common.output import print_error
from .service import FindApexCommand


def print_result(r: str, nocolor: bool = False):
    if nocolor:
        message = r
    else:
        message = colored(r, "blue")
    print(message, file=sys.stdout)


def main():
    parser = ArgumentParser()
    parser.add_argument(
        "domain", help="target domain")
    parser.add_argument(
        "--nocolor", help="disable colored outputs", action="store_true")
    config = parser.parse_args()

    def result_handler(domain: str):
        print_result(domain, config.nocolor)

    try:
        cmd = FindApexCommand(
            config.domain,
            on_result=result_handler)
    except Exception as e:
        print_error(str(e), config.nocolor)
        sys.exit(1)

    cmd.run()


if __name__ == "__main__":
    main()
