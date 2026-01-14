import os
from types import SimpleNamespace
from typing import TypeVar, Optional
from argparse import Namespace, ArgumentParser
from dataclasses import dataclass
from asset_store.repository.repository import Repository
from asset_store.repository.neo4j import NeoRepository
from dotenv import dotenv_values

def get_uri() -> str:
    env = {
        **os.environ,  
        **dotenv_values(".env"),  
    }
    if "NEO_URI" not in env:
        raise Exception("missing NEO_URI in environment")
    return env["NEO_URI"]

def get_creds() -> tuple[str, str]:
    env = {
        **os.environ,  
        **dotenv_values(".env"),  
    }
    if "NEO_USER" not in env:
        raise Exception("missing NEO_USER in environment")
    if "NEO_PASS" not in env:
        raise Exception("missing NEO_PASS in environment")
    return (env["NEO_USER"], env["NEO_PASS"])


Data = TypeVar("Data", bound=object)

class Context():
    source:    str
    config:    Optional[object] = None
    db:        Repository
    
    def __init__(self, source: str, config: Optional[Namespace] = None):
        self.source = source
        self.config = SimpleNamespace() if config is None else config
        self.db = NeoRepository(
            get_uri(),
            get_creds(),
            emit_events = True)

    def __enter__(self):
        self.db.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.db.__exit__(exc_type, exc, tb)

    @staticmethod
    def from_argument_parser(parser: ArgumentParser) -> 'Context':
        return Context(
            parser.prog,
            parser.parse_args())
