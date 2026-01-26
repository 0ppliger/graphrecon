import sys
from termcolor import colored


def print_error(
        e: str | Exception,
        nocolor: bool = False,
        silent: bool = False
):
    if silent:
        return

    if isinstance(e, Exception):
        _message = str(e)
    else:
        _message = e

    if nocolor:
        message = f"ERROR: {_message}"
    else:
        message = f"{colored('ERROR', 'red', attrs=['bold'])}: {_message}"
    print(message, file=sys.stderr)
