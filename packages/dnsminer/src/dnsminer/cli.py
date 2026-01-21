import argparse
import os
import re
import sys
from asset_store.repository.neo4j import NeoRepository
from asset_model import Product
from termcolor import colored
from enum import Enum
from argparse import ArgumentParser
import json
__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))


def print_success(product: Product):
    print(colored(product.name, "green", attrs=["bold"]),
          colored("found", "dark_grey"))


class ProductType(str, Enum):
    Software = "software"
    Hardware = "hardware"
    Service = "service"


def make_argument_parser() -> ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dnsminer",
        description="A simple tool that identifies services in DNS TXT records")
    parser.add_argument("-t", "--txt", help="A text record", action="append")
    return parser


def main():
    parser = make_argument_parser()
    config = parser.parse_args()

    if config.txt is None:
        parser.print_help()
        sys.exit(1)

    with open(os.path.join(__location__, "mapping.json")) as json_data:
        d = json.load(json_data)

    mapping: dict[str, Product] = {
        k: Product(
            id=d["id"],
            name=d["name"],
            type=d["type"]
        ) for k, d in d.items()
    }

    for txt in config.txt:
        for reg, product in mapping.items():
            if re.match(reg, txt):
                print_success(product)
