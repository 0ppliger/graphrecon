import common.cli_setup  # noqa: F401

import argparse
import sys
from termcolor import colored

from common.output import print_error

from .service import ExtractProductFromTxtCommand, ExtractProductsFromDomain

found = set()


def success_handler(
        product: str,
        txt: str,
        nocolor: bool = False,
        verbose: bool = False,
        silent: bool = False
):
    if silent:
        return

    prefix = ""
    suffix = ""
    if verbose:
        prefix = "FOUND: "
        if not nocolor:
            prefix = colored(prefix, 'blue', attrs=['bold'])

        suffix = f" {txt}"
        if not nocolor:
            suffix = colored(suffix, 'light_grey')

    if not nocolor:
        message = colored(product, 'blue')
    else:
        message = product

    if verbose or (not verbose and product not in found):
        print(prefix + message + suffix)

    found.add(product)


def failure_handler(
        txt: str,
        nocolor: bool = False,
        verbose: bool = False,
        silent: bool = False
):
    if not verbose:
        return

    prefix = "TRY: "
    if not nocolor:
        prefix = colored(prefix, 'light_grey', attrs=['bold'])

    if not nocolor:
        message = colored(txt, 'light_grey')
    else:
        message = txt

    print(prefix + message)


def main():
    parser = argparse.ArgumentParser(
        prog="dnsminer",
        description="""
        A simple tool that identifies services in DNS TXT records
        """)
    parser.add_argument(
        "--nocolor", help="disable colored output",
        action="store_true")

    action_group = parser.add_mutually_exclusive_group(required=True)

    action_group.add_argument(
        "-t", "--txt", help="A single text record")
    action_group.add_argument(
        "-d", "--domain", help="A domain to query")

    output_group = parser.add_mutually_exclusive_group()

    output_group.add_argument(
        "-v", "--verbose", help="show tries",
        action="store_true")
    output_group.add_argument(
        "-s", "--silent", help="disable outputs",
        action="store_true")

    config = parser.parse_args()

    if config.txt is not None:
        try:
            cmd = ExtractProductFromTxtCommand(
                config.txt,
                on_success=(lambda p, t: success_handler(
                    p, t, config.nocolor,
                    config.verbose,
                    config.silent)),
                on_failure=(lambda t: failure_handler(
                    t, config.nocolor,
                    config.verbose,
                    config.silent)),
            )
        except Exception as e:
            print_error(e)
            sys.exit(1)

        cmd.run()
        sys.exit(0)

    try:
        cmd = ExtractProductsFromDomain(
            config.domain,
            on_success=(lambda p, t: success_handler(
                p, t, config.nocolor,
                config.verbose,
                config.silent)),
            on_failure=(lambda t: failure_handler(
                t, config.nocolor,
                config.verbose,
                config.silent)),
            )
    except Exception as e:
        print_error(e)
        sys.exit(1)

    cmd.run()


if __name__ == "__main__":
    main()
