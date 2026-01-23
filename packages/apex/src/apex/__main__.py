import sys
from argparse import ArgumentParser
from apex import apex, InvalidDomain
from termcolor import colored


def print_error(e: Exception, nocolor: bool = False):
    if nocolor:
        message = f"ERROR: {str(e)}"
    else:
        message = f"{colored('ERROR', 'red', attrs=['bold'])}: {str(e)}"
    print(message, file=sys.stderr)


def print_result(r: str, nocolor: bool = False):
    if nocolor:
        message = r
    else:
        message = colored(r, "green")
    print(message, file=sys.stdout)


def main():
    parser = ArgumentParser()
    parser.add_argument(
        "domain",
        help="target domain")
    parser.add_argument(
        "--nocolor",
        help="disable colored outputs",
        action="store_true")
    config = parser.parse_args()

    try:
        apex_domain = apex(config.domain)
        print_result(apex_domain, config.nocolor)
    except InvalidDomain as e:
        print_error(e, config.nocolor)


if __name__ == "__main__":
    main()
