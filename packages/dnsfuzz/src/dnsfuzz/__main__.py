import sys
from argparse import ArgumentParser
import asyncio
from graphrecon_lib import Context
import signal
from dnsfuzz import DNSFuzz


def sigint_handler(sig: int, _):
    print("exited by user")
    sys.exit(1)


signal.signal(signal.SIGINT, sigint_handler)


def success_handler(domain: str):
    print(f"Found: {domain}")


def failure_handler(domain: str):
    print(f"Try: {domain}")


async def __async_main():
    parser = ArgumentParser(
        prog="dnsfuzz",
        description="A parrallel bruteforce program")
    parser.add_argument(
        "-w", "--wordlist", help="path to wordlist", required=True)
    parser.add_argument(
        "-d", "--domain", help="target domain", required=True)
    parser.add_argument(
        "-v", "--verbose", help="show tries", action="store_true")
    parser.add_argument(
        "-B", "--batch-size", help="number of requests send simultaneously", type=int, default=10)
    parser.add_argument(
        "-D", "--delay", help="delay between each batch (in ms)", type=int, default=300)

    with Context.from_argument_parser(parser) as ctx:
        try:
            fuzzer = DNSFuzz(
                domain=ctx.config.domain,
                wordlist=ctx.config.wordlist,
                rate_limiter_delay=ctx.config.delay,
                rate_limiter_batch=ctx.config.batch_size,
                on_success=success_handler,
                on_failure=failure_handler
            )
        except Exception as e:
            print(e)
            sys.exit(1)

        tasks: list[asyncio.Task] = []
        async for sub in fuzzer.fuzz(ctx):
            tasks.append(sub)
        asyncio.gather(*tasks)


def main():
    asyncio.run(__async_main())
