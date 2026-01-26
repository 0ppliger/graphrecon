import sys
import signal


def sigint_handler(sig: int, _):
    print("exited by user", file=sys.stderr)
    sys.exit(1)


signal.signal(signal.SIGINT, sigint_handler)
