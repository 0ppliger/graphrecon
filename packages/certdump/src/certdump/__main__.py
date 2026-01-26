import common.cli_setup  # noqa: F401

# Lack support for :
# - TLSCertificate -[subject_contact]-> ContactRecord
# - TLSCertificate -[issuer_contact]-> ContactRecord

from argparse import ArgumentParser
from asset_store.repository.neo4j import NeoRepository
from termcolor import colored

from .service import DumpCertificateCommand


def print_success(obj_type: str, obj: str):
    print(f"{colored(obj_type, 'blue', attrs=['bold'])}: {colored(obj, 'blue')}")


def main():
    parser = ArgumentParser(
        description="Dump TLS certificate.",
        prog="certdump"
    )
    parser.add_argument("-d", "--domain",
                        help="the target domain",
                        required=True)

    config = parser.parse_args()

    store = NeoRepository("neo4j://localhost", ("neo4j", "password"))

    with store:
        cmd = DumpCertificateCommand(
            config.domain,
            store,
            on_success=lambda t, o: print_success(t, o)
        )

        cmd.run()


if __name__ == "__main__":
    main()
