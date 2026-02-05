import common.cli_setup  # noqa: F401

import sys
import asyncio
from argparse import ArgumentParser
from oam_client import BrokerClient
from termcolor import colored

from common.output import print_error
from .service import FuzzDNSCommand


def success_handler(
        domain: str,
        nocolor: bool = False,
        verbose: bool = False,
        silent: bool = False
):
    if silent:
        return

    prefix = ""
    if verbose:
        prefix = "FOUND: "
        if not nocolor:
            prefix = colored(prefix, 'blue', attrs=['bold'])

    if not nocolor:
        message = colored(domain, 'blue')
    else:
        message = domain

    print(prefix + message)


def failure_handler(
        domain: str,
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
        message = colored(domain, 'light_grey')
    else:
        message = domain

    print(prefix + message)


async def __async_main():
    parser = ArgumentParser(
        prog="dnsfuzz",
        description="A parrallel bruteforce program")
    parser.add_argument(
        "-w", "--wordlist", help="path to wordlist",
        required=True)
    parser.add_argument(
        "-d", "--domain", help="target domain",
        required=True)
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
        "--nocolor", help="disable colored output",
        action="store_true")
    parser.add_argument(
        "--nostore", help="disable asset store",
        action="store_true")

    output_group = parser.add_mutually_exclusive_group()

    output_group.add_argument(
        "-v", "--verbose", help="show tries",
        action="store_true")
    output_group.add_argument(
        "-s", "--silent", help="disable outputs",
        action="store_true")

    config = parser.parse_args()

    try:
        store = BrokerClient("https://localhost", verify=False)
    except Exception as e:
        print_error(e, config.nocolor)
        sys.exit(1)

    try:
        fuzzer = FuzzDNSCommand(
            domain=config.domain,
            wordlist=config.wordlist,
            on_success=(lambda d: success_handler(
                d, config.nocolor,
                config.verbose,
                config.silent)),
            on_failure=(lambda d: failure_handler(
                d, config.nocolor,
                config.verbose,
                config.silent)),
            resolv=config.resolv,
            store=store,
            ratelimiter_batch=config.batch_size,
            ratelimiter_delay=config.delay,
            disable_store=config.nostore
        )
    except Exception as e:
        print_error(e)
        sys.exit(1)

    await fuzzer.run()


def main():
    asyncio.run(__async_main())


if __name__ == "__main__":
    main()
