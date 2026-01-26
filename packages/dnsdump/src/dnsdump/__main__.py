import common.cli_setup  # noqa: F401

import sys
import json
from argparse import ArgumentParser
from termcolor import colored
from pygments import highlight, lexers, formatters

from asset_store.repository.neo4j import NeoRepository
from .service import DumpDNSCommand

from common.output import print_error


def _get_displayable_name(
        name: str,
        color: str,
        nocolor: bool = False
) -> str:
    if nocolor:
        return name
    else:
        return colored(name, color, attrs=["bold"])


def _get_displayable_data(
        json_data: str,
        nocolor: bool = False
) -> str:
    if nocolor:
        return json_data + "\n"
    else:
        colorful_json_data = highlight(
            json_data,
            lexers.JsonLexer(),
            formatters.TerminalFormatter())
        return colorful_json_data


def _get_displayable_error(
        error: str,
        nocolor: bool = False
) -> str:
    if nocolor:
        return error
    else:
        return colored(error, "light_grey")


def display_success(
        name: str,
        data: dict,
        nocolor: bool = False,
        silent: bool = False
):
    if silent:
        return

    json_data = json.dumps(data)
    print(_get_displayable_name(name, "green", nocolor), end=" ")
    print(_get_displayable_data(json_data, nocolor), end="")


def display_fail(
        name: str,
        nocolor: bool = False,
        silent: bool = False,
        verbose: bool = False
):
    if silent:
        return

    if verbose:
        print(_get_displayable_name(name, "yellow", nocolor), end=" ")
        print(_get_displayable_error("No record", nocolor))


def main():
    parser = ArgumentParser(
        prog="dnsdump",
        description="Dump all DNS records by requesting every RRType.")
    parser.add_argument(
        "-d", "--domain", help="Domain name to query",
        type=str, required=True)
    parser.add_argument(
        "-r", "--resolv", help="Path to the resolver configuration file",
        default="./resolve.conf")
    parser.add_argument(
        "-rb", "--batch-size", help="rate limiter batch size",
        type=int, default=10)
    parser.add_argument(
        "-rd", "--delay", help="rate limiter delay between batches (in ms)",
        type=int, default=300)
    parser.add_argument(
        "--nocolor", help="Disable colors on stdout",
        action="store_true")
    parser.add_argument(
        "--nosource", help="Disable source tags in OAM",
        action="store_true")

    output_group = parser.add_mutually_exclusive_group()

    output_group.add_argument(
        "-v", "--verbose", help="Show failed attempts",
        action="store_true")
    output_group.add_argument(
        "-s", "--silent", help="Show failed attempts",
        action="store_true")

    config = parser.parse_args()

    try:
        store = NeoRepository("neo4j://localhost", ("neo4j", "password"))
    except Exception as e:
        print_error(e, config.nocolor, config.silent)
        sys.exit(1)

    def success_handler(rdtype: str, data: dict):
        display_success(rdtype, data, config.nocolor, config.silent)

    def failure_handler(rdtype: str):
        display_fail(rdtype, config.nocolor, config.silent, config.verbose)

    with store:
        try:
            cmd = DumpDNSCommand(
                domain=config.domain,
                resolv=config.resolv,
                store=store,
                on_success=success_handler,
                on_failure=failure_handler,
                ratelimiter_batch=config.batch_size,
                ratelimiter_delay=config.delay,
            )
        except Exception as e:
            print_error(e, config.nocolor, config.silent)
            sys.exit(1)

        cmd.run()


if __name__ == "__main__":
    main()
