import json
import sys
from argparse import ArgumentParser
from termcolor import colored
from pygments import highlight, lexers, formatters
from dnsdump import (
    DNSDump,
    DNSDumpAnswer,
    DNSDumpNoAnswer,
    DNSDumpQueryFail)
from graphrecon_lib import Context


def _get_displayable_name(ctx: Context, name: str, color: str = "green") -> str:
    if ctx.config.nocolor:
        return name
    else:
        return colored(name, color, attrs=["bold"])


def _get_displayable_data(ctx: Context, json_data: str) -> str:
    if ctx.config.nocolor:
        return json_data + "\n"
    else:
        colorful_json_data = highlight(
            json_data,
            lexers.JsonLexer(),
            formatters.TerminalFormatter())
        return colorful_json_data


def _get_displayable_error(ctx: Context, error: str) -> str:
    if ctx.config.nocolor:
        return error
    else:
        return colored(error, "light_grey")


def display_success(ctx: Context, name: str, data: dict) -> None:
    json_data = json.dumps(data)
    if not ctx.config.silent:
        print(_get_displayable_name(ctx, name), end=" ")
        print(_get_displayable_data(ctx, json_data), end="")


def display_fail(ctx: Context, name: str, error: str) -> None:
    if not ctx.config.silent and ctx.config.verbose:
        print(_get_displayable_name(ctx, name, "yellow"), end=" ")
        print(_get_displayable_error(ctx, error))


def make_argument_parser() -> ArgumentParser:
    parser = ArgumentParser(
        prog="dnsdump",
        description="Dump all DNS records by requesting every RRType.")
    parser.add_argument("-d", "--domain", type=str, help="Domain name to query", required=True)
    parser.add_argument("-v", "--verbose", help="Show failed attempts", action="store_true")
    parser.add_argument("-s", "--silent", help="Show failed attempts", action="store_true")
    parser.add_argument("-r", "--resolv", help="Path to the resolver configuration file", default="./resolve.conf")
    parser.add_argument("--nocolor", help="Disable colors on stdout", action="store_true")
    parser.add_argument("--nosource", help="Disable source tags in OAM", action="store_true")
    return parser


def main():
    parser = make_argument_parser()

    with Context.from_argument_parser(parser) as ctx:

        if ctx.config.silent and ctx.config.verbose:
            print("*warning*: you've enabled both --verbose and --silent flags.",
                  file=sys.stderr)

        dnsdump = DNSDump(ctx)

        dump = dnsdump.dump_domain(ctx.config.domain)

        for answer in dump:
            match answer:
                case DNSDumpAnswer():
                    display_success(ctx, answer.rdtype, answer.data)
                case DNSDumpNoAnswer():
                    display_fail(ctx, answer.rdtype, "No such entry")
                case DNSDumpQueryFail():
                    display_fail(ctx, answer.rdtype, "Query fail")
