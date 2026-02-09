import common.cli_setup  # noqa: F401

# Lack support for :
# - TLSCertificate -[subject_contact]-> ContactRecord
# - TLSCertificate -[issuer_contact]-> ContactRecord

import sys
import asyncio
from argparse import ArgumentParser
from oam_client import AsyncBrokerClient
from termcolor import colored
from common.output import print_error
from .service import DumpCertificateCommand


def print_success(obj_type: str, obj: str):
    print(f"{colored(obj_type, 'blue', attrs=['bold'])}: {colored(obj, 'blue')}")


async def async_main():
    parser = ArgumentParser(
        description="Dump TLS certificate.",
        prog="certdump"
    )
    parser.add_argument("-d", "--domain",
                        help="the target domain",
                        required=True)

    config = parser.parse_args()

    try:
        store = AsyncBrokerClient("https://localhost", verify=False)
    except Exception as e:
        print_error(e, config.nocolor, config.silent)
        sys.exit(1)

    cmd = DumpCertificateCommand(
        config.domain,
        store,
        on_success=lambda t, o: print_success(t, o)
    )

    await cmd.run()


def main():
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
